#!/usr/bin/env python3
"""
Network Packet Monitoring and Ethernet Frame Analysis System
------------------------------------------------------------
Captures (Linux AF_PACKET raw socket) or reads (.pcap file) Ethernet frames,
decodes Ethernet II / VLAN / ARP / IPv4 / IPv6 / ICMP / TCP / UDP headers,
prints a per-frame analysis, and produces a traffic summary.

Usage examples:
    sudo python3 packet_monitor.py -i eth0 -c 50            # live capture, 50 frames
    sudo python3 packet_monitor.py -i eth0 -t 30 -w out.pcap  # capture 30 s, save
    python3 packet_monitor.py -r sample.pcap                # analyse a pcap file
    python3 packet_monitor.py -r sample.pcap --hex --filter tcp
    python3 packet_monitor.py -r sample.pcap --csv report.csv

Use only on networks you own or are authorised to monitor.
"""
import argparse
import csv
import socket
import struct
import sys
import time
from collections import Counter, defaultdict

# ----------------------------------------------------------------- constants
ETHERTYPES = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
    0x8100: "802.1Q VLAN", 0x88A8: "802.1ad QinQ", 0x8847: "MPLS",
    0x88CC: "LLDP", 0x8863: "PPPoE Discovery", 0x8864: "PPPoE Session",
}
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP",
                47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF"}
TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
             (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request",
              11: "Time Exceeded"}
WELL_KNOWN_PORTS = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
                    123: "NTP", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
                    8080: "HTTP-alt"}
ETH_HEADER_LEN = 14
ETH_MIN_FRAME = 60     # without FCS
ETH_MAX_FRAME = 1514   # without FCS, standard MTU 1500


# ------------------------------------------------------------------- helpers
def fmt_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def mac_kind(raw: bytes) -> str:
    if raw == b"\xff" * 6:
        return "broadcast"
    if raw[0] & 1:
        return "multicast"
    if raw[0] & 2:
        return "locally-administered unicast"
    return "unicast"


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {off:04x}  {hx:<{width * 3}} {asc}")
    return "\n".join(lines)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# ------------------------------------------------------------------- parsing
def parse_ethernet(frame: bytes) -> dict:
    """Decode a full Ethernet frame into a dict of layers."""
    info = {"length": len(frame), "layers": [], "errors": []}
    if len(frame) < ETH_HEADER_LEN:
        info["errors"].append("frame shorter than Ethernet header")
        return info

    dst, src, etype = struct.unpack("!6s6sH", frame[:14])
    eth = {"layer": "Ethernet", "dst": fmt_mac(dst), "src": fmt_mac(src),
           "dst_kind": mac_kind(dst), "ethertype": etype}
    offset = 14
    vlan = None
    while etype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
        tci, etype = struct.unpack("!HH", frame[offset:offset + 4])
        vlan = {"layer": "802.1Q", "pcp": tci >> 13, "dei": (tci >> 12) & 1,
                "vid": tci & 0x0FFF}
        offset += 4
    eth["ethertype"] = etype
    if etype < 1536:
        eth["type_name"] = f"802.3 length={etype}"
    else:
        eth["type_name"] = ETHERTYPES.get(etype, f"0x{etype:04x}")
    info["layers"].append(eth)
    if vlan:
        info["layers"].append(vlan)

    if len(frame) < ETH_MIN_FRAME:
        info["errors"].append(f"runt frame ({len(frame)} < {ETH_MIN_FRAME} bytes)"
                              " - may be capture offload/padding artefact")
    if len(frame) > ETH_MAX_FRAME + (4 if vlan else 0):
        info["errors"].append(f"oversize frame ({len(frame)} bytes) - jumbo or offload")

    payload = frame[offset:]
    if etype == 0x0800:
        parse_ipv4(payload, info)
    elif etype == 0x0806:
        parse_arp(payload, info)
    elif etype == 0x86DD:
        parse_ipv6(payload, info)
    return info


def parse_arp(data: bytes, info: dict):
    if len(data) < 28:
        info["errors"].append("truncated ARP")
        return
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
    sha, spa, tha, tpa = struct.unpack("!6s4s6s4s", data[8:28])
    info["layers"].append({
        "layer": "ARP", "op": {1: "request", 2: "reply"}.get(op, str(op)),
        "sender_mac": fmt_mac(sha), "sender_ip": socket.inet_ntoa(spa),
        "target_mac": fmt_mac(tha), "target_ip": socket.inet_ntoa(tpa)})


def parse_ipv4(data: bytes, info: dict):
    if len(data) < 20:
        info["errors"].append("truncated IPv4 header")
        return
    vihl, tos, tlen, ident, ffrag, ttl, proto, csum = struct.unpack("!BBHHHBBH", data[:12])
    src, dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        info["errors"].append("bad IPv4 IHL")
        return
    ok = internet_checksum(data[:ihl]) == 0
    ip = {"layer": "IPv4", "src": src, "dst": dst, "ttl": ttl, "id": ident,
          "proto": proto, "proto_name": IP_PROTOCOLS.get(proto, str(proto)),
          "total_len": tlen, "header_len": ihl, "dscp": tos >> 2,
          "df": bool(ffrag & 0x4000), "mf": bool(ffrag & 0x2000),
          "frag_offset": (ffrag & 0x1FFF) * 8, "checksum_ok": ok}
    info["layers"].append(ip)
    if not ok:
        info["errors"].append("IPv4 header checksum mismatch "
                              "(may be TX checksum offload on local capture)")
    body = data[ihl:tlen] if tlen >= ihl else data[ihl:]
    if ip["frag_offset"] == 0:
        parse_transport(proto, body, info, src, dst)


def parse_ipv6(data: bytes, info: dict):
    if len(data) < 40:
        info["errors"].append("truncated IPv6 header")
        return
    vtf, plen, nxt, hop = struct.unpack("!IHBB", data[:8])
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    info["layers"].append({"layer": "IPv6", "src": src, "dst": dst, "hop_limit": hop,
                           "next_header": IP_PROTOCOLS.get(nxt, str(nxt)),
                           "payload_len": plen, "flow_label": vtf & 0xFFFFF})
    parse_transport(nxt, data[40:], info, src, dst)


def parse_transport(proto: int, data: bytes, info: dict, src: str, dst: str):
    if proto == 6 and len(data) >= 20:
        sp, dp, seq, ack, off_flags, win, csum, urg = struct.unpack("!HHIIHHHH", data[:20])
        flags = [n for bit, n in TCP_FLAGS if (off_flags & 0xFF) & bit]
        hl = (off_flags >> 12) * 4
        info["layers"].append({"layer": "TCP", "sport": sp, "dport": dp, "seq": seq,
                               "ack": ack, "flags": flags, "window": win,
                               "payload_len": max(0, len(data) - hl)})
        info["payload"] = data[hl:]
    elif proto == 17 and len(data) >= 8:
        sp, dp, ln, csum = struct.unpack("!HHHH", data[:8])
        info["layers"].append({"layer": "UDP", "sport": sp, "dport": dp, "length": ln})
        info["payload"] = data[8:]
    elif proto in (1, 58) and len(data) >= 4:
        t, c = struct.unpack("!BB", data[:2])
        name = ICMP_TYPES.get(t, f"type {t}") if proto == 1 else f"type {t}"
        info["layers"].append({"layer": "ICMP" if proto == 1 else "ICMPv6",
                               "type": t, "code": c, "type_name": name})
    elif proto in (6, 17, 1):
        info["errors"].append("truncated transport header")


def summary_line(info: dict) -> str:
    L = {l["layer"]: l for l in info["layers"]}
    if "TCP" in L:
        t, ip = L["TCP"], L.get("IPv4") or L.get("IPv6")
        return (f"TCP  {ip['src']}:{t['sport']} -> {ip['dst']}:{t['dport']} "
                f"[{','.join(t['flags']) or '-'}] len={t['payload_len']}")
    if "UDP" in L:
        u, ip = L["UDP"], L.get("IPv4") or L.get("IPv6")
        return f"UDP  {ip['src']}:{u['sport']} -> {ip['dst']}:{u['dport']} len={u['length'] - 8}"
    if "ICMP" in L:
        return f"ICMP {L['IPv4']['src']} -> {L['IPv4']['dst']} {L['ICMP']['type_name']}"
    if "ICMPv6" in L:
        return f"ICMPv6 {L['IPv6']['src']} -> {L['IPv6']['dst']} {L['ICMPv6']['type_name']}"
    if "ARP" in L:
        a = L["ARP"]
        if a["op"] == "request":
            return f"ARP  Who has {a['target_ip']}? Tell {a['sender_ip']}"
        return f"ARP  {a['sender_ip']} is at {a['sender_mac']}"
    if "IPv4" in L:
        return f"IPv4 {L['IPv4']['src']} -> {L['IPv4']['dst']} proto={L['IPv4']['proto_name']}"
    if "IPv6" in L:
        return f"IPv6 {L['IPv6']['src']} -> {L['IPv6']['dst']}"
    return f"Ethernet {L['Ethernet']['src']} -> {L['Ethernet']['dst']} {L['Ethernet']['type_name']}" \
        if "Ethernet" in L else "unparseable frame"


# ------------------------------------------------------------------- filters
def make_filter(expr):
    """Simple filter: protocol names and host=/port= tokens joined with 'and'."""
    if not expr:
        return lambda info: True
    tokens = [t.strip().lower() for t in expr.replace(" and ", ",").split(",") if t.strip()]

    def match(info):
        names = {l["layer"].lower() for l in info["layers"]}
        for tok in tokens:
            if tok.startswith("host="):
                h = tok[5:]
                if not any(l.get("src") == h or l.get("dst") == h or
                           l.get("sender_ip") == h or l.get("target_ip") == h
                           for l in info["layers"]):
                    return False
            elif tok.startswith("port="):
                p = int(tok[5:])
                if not any(l.get("sport") == p or l.get("dport") == p for l in info["layers"]):
                    return False
            elif tok.startswith("mac="):
                m = tok[4:]
                eth = info["layers"][0]
                if m not in (eth.get("src"), eth.get("dst")):
                    return False
            elif tok not in names:
                return False
        return True
    return match


# ------------------------------------------------------------------ statistics
class Stats:
    def __init__(self):
        self.frames = 0
        self.bytes = 0
        self.proto = Counter()
        self.ethertype = Counter()
        self.mac_pairs = Counter()
        self.src_mac_bytes = defaultdict(int)
        self.ip_pairs = Counter()
        self.ports = Counter()
        self.sizes = Counter()
        self.cast = Counter()
        self.tcp_flags = Counter()
        self.arp_ip_to_macs = defaultdict(set)
        self.errors = Counter()
        self.first_ts = None
        self.last_ts = None

    def add(self, info, ts):
        self.frames += 1
        self.bytes += info["length"]
        self.first_ts = ts if self.first_ts is None else self.first_ts
        self.last_ts = ts
        if not info["layers"]:
            self.errors["unparseable"] += 1
            return
        eth = info["layers"][0]
        self.ethertype[eth["type_name"]] += 1
        self.cast[eth["dst_kind"]] += 1
        self.mac_pairs[(eth["src"], eth["dst"])] += 1
        self.src_mac_bytes[eth["src"]] += info["length"]
        n = info["length"]
        bucket = ("<64" if n < 64 else "64-127" if n < 128 else "128-255" if n < 256 else
                  "256-511" if n < 512 else "512-1023" if n < 1024 else "1024-1518" if n <= 1518
                  else ">1518")
        self.sizes[bucket] += 1
        top = info["layers"][-1]["layer"]
        self.proto[top] += 1
        for l in info["layers"]:
            if l["layer"] in ("IPv4", "IPv6"):
                self.ip_pairs[(l["src"], l["dst"])] += 1
            if l["layer"] in ("TCP", "UDP"):
                self.ports[(l["layer"], min(l["sport"], l["dport"])
                            if min(l["sport"], l["dport"]) in WELL_KNOWN_PORTS
                            else l["dport"])] += 1
            if l["layer"] == "TCP":
                for f in l["flags"]:
                    self.tcp_flags[f] += 1
            if l["layer"] == "ARP" and l["op"] == "reply":
                self.arp_ip_to_macs[l["sender_ip"]].add(l["sender_mac"])
        for e in info["errors"]:
            self.errors[e.split(" (")[0]] += 1

    def report(self) -> str:
        out = ["", "=" * 70, "TRAFFIC SUMMARY", "=" * 70]
        dur = (self.last_ts - self.first_ts) if self.frames > 1 else 0
        out.append(f"Frames: {self.frames}   Bytes: {self.bytes}   Duration: {dur:.3f}s")
        if dur > 0:
            out.append(f"Average rate: {self.bytes * 8 / dur / 1000:.2f} kbit/s, "
                       f"{self.frames / dur:.1f} frames/s")
        if self.frames:
            out.append(f"Average frame size: {self.bytes / self.frames:.1f} bytes")

        def block(title, counter, key=str, n=10):
            out.append(f"\n{title}")
            for k, v in counter.most_common(n):
                pct = 100 * v / max(1, self.frames)
                out.append(f"  {key(k):<52} {v:>6}  ({pct:5.1f}%)")

        block("Highest-layer protocol", self.proto)
        block("EtherType", self.ethertype)
        block("Destination type", self.cast)
        block("Frame size distribution (bytes)", self.sizes)
        block("Top MAC conversations", self.mac_pairs, lambda k: f"{k[0]} -> {k[1]}")
        block("Top IP conversations", self.ip_pairs, lambda k: f"{k[0]} -> {k[1]}")
        block("Top ports", self.ports,
              lambda k: f"{k[0]} {k[1]} {WELL_KNOWN_PORTS.get(k[1], '')}".strip())
        if self.tcp_flags:
            block("TCP flags seen", self.tcp_flags)
        out.append("\nSecurity / anomaly checks")
        found = False
        for ip, macs in self.arp_ip_to_macs.items():
            if len(macs) > 1:
                found = True
                out.append(f"  [!] ARP: {ip} claimed by multiple MACs {sorted(macs)} "
                           "(possible ARP spoofing)")
        syn = self.tcp_flags.get("SYN", 0)
        synack_est = self.tcp_flags.get("ACK", 0)
        if syn > 20 and syn > 3 * max(1, synack_est):
            found = True
            out.append(f"  [!] TCP: {syn} SYN vs {synack_est} ACK (possible SYN scan/flood)")
        for e, c in self.errors.items():
            found = True
            out.append(f"  [i] {e}: {c} frame(s)")
        if not found:
            out.append("  none detected")
        return "\n".join(out)


# ---------------------------------------------------------------- pcap file I/O
PCAP_MAGIC = 0xA1B2C3D4


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
        self.f.flush()

    def write(self, ts: float, frame: bytes):
        sec = int(ts)
        self.f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
        self.f.write(frame)
        self.f.flush()

    def close(self):
        self.f.close()


def read_pcap(path):
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise ValueError("not a pcap file")
        magic = struct.unpack("<I", head[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            e = "<"
        elif struct.unpack(">I", head[:4])[0] in (0xA1B2C3D4, 0xA1B23C4D):
            e = ">"
        else:
            raise ValueError("unsupported capture format (only classic pcap)")
        nano = struct.unpack(e + "I", head[:4])[0] == 0xA1B23C4D
        linktype = struct.unpack(e + "I", head[20:24])[0]
        if linktype != 1:
            raise ValueError(f"link type {linktype} is not Ethernet")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, incl, orig = struct.unpack(e + "IIII", h)
            data = f.read(incl)
            yield sec + frac / (1e9 if nano else 1e6), data


# ----------------------------------------------------------------- live capture
def live_capture(iface, timeout=None, count=None):
    if not sys.platform.startswith("linux"):
        sys.exit("Live capture needs Linux (AF_PACKET). Use -r to analyse a pcap file.")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        if iface:
            s.bind((iface, 0))
    except PermissionError:
        sys.exit("Permission denied: run with sudo / root.")
    except OSError as e:
        sys.exit(f"Cannot open interface {iface!r}: {e}")
    s.settimeout(1.0)
    start, n = time.time(), 0
    try:
        while True:
            if timeout and time.time() - start >= timeout:
                break
            if count and n >= count:
                break
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            n += 1
            yield time.time(), data
    except KeyboardInterrupt:
        print("\n[stopped by user]")
    finally:
        s.close()


# ------------------------------------------------------------------ presentation
def print_detail(no, ts, info, show_hex, frame):
    print(f"\nFrame {no}  {time.strftime('%H:%M:%S', time.localtime(ts))}"
          f".{int((ts % 1) * 1e6):06d}  {info['length']} bytes")
    for l in info["layers"]:
        n = l["layer"]
        if n == "Ethernet":
            print(f"  Ethernet : dst={l['dst']} ({l['dst_kind']})  src={l['src']}  "
                  f"type={l['type_name']} (0x{l['ethertype']:04x})")
        elif n == "802.1Q":
            print(f"  VLAN     : id={l['vid']} priority={l['pcp']} dei={l['dei']}")
        elif n == "ARP":
            print(f"  ARP      : {l['op']}  sender={l['sender_ip']}/{l['sender_mac']}  "
                  f"target={l['target_ip']}/{l['target_mac']}")
        elif n == "IPv4":
            fl = ("DF " if l["df"] else "") + ("MF" if l["mf"] else "")
            print(f"  IPv4     : {l['src']} -> {l['dst']}  proto={l['proto_name']}  ttl={l['ttl']}  "
                  f"id={l['id']}  len={l['total_len']}  flags={fl.strip() or '-'}  "
                  f"csum={'ok' if l['checksum_ok'] else 'BAD'}")
        elif n == "IPv6":
            print(f"  IPv6     : {l['src']} -> {l['dst']}  next={l['next_header']}  hop={l['hop_limit']}")
        elif n == "TCP":
            print(f"  TCP      : {l['sport']} -> {l['dport']}  flags=[{','.join(l['flags'])}]  "
                  f"seq={l['seq']} ack={l['ack']} win={l['window']} payload={l['payload_len']}B")
        elif n == "UDP":
            print(f"  UDP      : {l['sport']} -> {l['dport']}  length={l['length']}")
        elif n in ("ICMP", "ICMPv6"):
            print(f"  {n:<9}: {l['type_name']} (type={l['type']} code={l['code']})")
    for e in info["errors"]:
        print(f"  [!] {e}")
    if show_hex:
        print(hexdump(frame))


def main():
    ap = argparse.ArgumentParser(description="Network packet monitor & Ethernet frame analyser")
    ap.add_argument("-i", "--interface", help="interface for live capture (e.g. eth0)")
    ap.add_argument("-r", "--read", help="read frames from a pcap file")
    ap.add_argument("-w", "--write", help="save captured frames to a pcap file")
    ap.add_argument("-c", "--count", type=int, help="stop after N frames")
    ap.add_argument("-t", "--time", type=float, help="stop after N seconds (live)")
    ap.add_argument("-f", "--filter", help="e.g. 'tcp', 'udp,port=53', 'arp', 'host=10.0.0.5'")
    ap.add_argument("--hex", action="store_true", help="show hex dump of each frame")
    ap.add_argument("--brief", action="store_true", help="one line per frame")
    ap.add_argument("--csv", help="export per-frame records to CSV")
    ap.add_argument("--no-summary", action="store_true")
    a = ap.parse_args()

    if not a.read and not a.interface:
        ap.error("give -r FILE or -i INTERFACE")
    source = read_pcap(a.read) if a.read else live_capture(a.interface, a.time, a.count)
    writer = PcapWriter(a.write) if a.write else None
    flt, stats = make_filter(a.filter), Stats()
    csvf = csv.writer(open(a.csv, "w", newline="")) if a.csv else None
    if csvf:
        csvf.writerow(["no", "time", "length", "src_mac", "dst_mac", "ethertype",
                       "summary", "errors"])
    shown = 0
    try:
        for no, (ts, frame) in enumerate(source, 1):
            info = parse_ethernet(frame)
            if not flt(info):
                continue
            shown += 1
            stats.add(info, ts)
            if writer:
                writer.write(ts, frame)
            if csvf and info["layers"]:
                e = info["layers"][0]
                csvf.writerow([no, f"{ts:.6f}", info["length"], e["src"], e["dst"],
                               e["type_name"], summary_line(info), "; ".join(info["errors"])])
            if a.brief:
                print(f"{no:>5} {ts:.6f} {info['length']:>5}  {summary_line(info)}")
            else:
                print_detail(no, ts, info, a.hex, frame)
            if a.count and a.read and shown >= a.count:
                break
    except (ValueError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")
    finally:
        if writer:
            writer.close()
    if not a.no_summary:
        print(stats.report())


if __name__ == "__main__":
    main()
