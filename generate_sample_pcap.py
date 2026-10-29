#!/usr/bin/env python3
"""Generates a synthetic Ethernet capture (sample.pcap) for testing packet_monitor.py
without needing root or a live network. Frames are built by hand, byte by byte."""
import socket
import struct
import sys
from packet_monitor import PcapWriter, internet_checksum


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def eth(dst, src, etype, payload):
    f = mac(dst) + mac(src) + struct.pack("!H", etype) + payload
    return f + b"\x00" * max(0, 60 - len(f))      # pad to Ethernet minimum


def ipv4(src, dst, proto, payload, ttl=64, ident=1):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000,
                      ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    csum = internet_checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:] + payload


def tcp(sp, dp, seq, ack, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 64240, 0, 0) + data


def udp(sp, dp, data):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data


def arp(op, smac, sip, tmac, tip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(smac) + socket.inet_aton(sip) + \
        mac(tmac) + socket.inet_aton(tip)


def main(path):
    A, B, GW = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:fe"
    BC = "ff:ff:ff:ff:ff:ff"
    ipA, ipB, ipGW, ext = "192.168.1.10", "192.168.1.20", "192.168.1.1", "93.184.216.34"
    t = 1_700_000_000.0
    frames = []

    def add(dt, f):
        nonlocal t
        t += dt
        frames.append((t, f))

    # ARP resolution of the gateway
    add(0, eth(BC, A, 0x0806, arp(1, A, ipA, "00:00:00:00:00:00", ipGW)))
    add(0.001, eth(A, GW, 0x0806, arp(2, GW, ipGW, A, ipA)))
    # DNS query / response
    dns_q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    add(0.01, eth(GW, A, 0x0800, ipv4(ipA, "8.8.8.8", 17, udp(53211, 53, dns_q))))
    add(0.02, eth(A, GW, 0x0800, ipv4("8.8.8.8", ipA, 17, udp(53, 53211, dns_q + b"\xc0\x0c" * 4))))
    # TCP three-way handshake + HTTP request/response + teardown
    add(0.01, eth(GW, A, 0x0800, ipv4(ipA, ext, 6, tcp(40000, 80, 1000, 0, 0x02))))
    add(0.03, eth(A, GW, 0x0800, ipv4(ext, ipA, 6, tcp(80, 40000, 5000, 1001, 0x12))))
    add(0.001, eth(GW, A, 0x0800, ipv4(ipA, ext, 6, tcp(40000, 80, 1001, 5001, 0x10))))
    req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: demo\r\n\r\n"
    add(0.002, eth(GW, A, 0x0800, ipv4(ipA, ext, 6, tcp(40000, 80, 1001, 5001, 0x18, req))))
    body = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"x" * 1000
    add(0.04, eth(A, GW, 0x0800, ipv4(ext, ipA, 6, tcp(80, 40000, 5001, 1001 + len(req), 0x18, body))))
    add(0.001, eth(GW, A, 0x0800, ipv4(ipA, ext, 6, tcp(40000, 80, 1001 + len(req), 5001 + len(body), 0x11))))
    add(0.03, eth(A, GW, 0x0800, ipv4(ext, ipA, 6, tcp(80, 40000, 5001 + len(body), 1002 + len(req), 0x11))))
    # HTTPS
    add(0.1, eth(GW, A, 0x0800, ipv4(ipA, ext, 6, tcp(40001, 443, 77, 0, 0x02))))
    # ICMP echo request/reply (A <-> B)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"abcdefgh"
    icmp = icmp[:2] + struct.pack("!H", internet_checksum(icmp)) + icmp[4:]
    add(0.2, eth(B, A, 0x0800, ipv4(ipA, ipB, 1, icmp)))
    rep = b"\x00" + icmp[1:]
    add(0.001, eth(A, B, 0x0800, ipv4(ipB, ipA, 1, rep, ttl=128)))
    # Broadcast DHCP-style UDP
    add(0.3, eth(BC, B, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67, b"\x01" * 40))))
    # 802.1Q VLAN-tagged frame
    inner = ipv4(ipB, ipA, 17, udp(5000, 5001, b"vlan test"))
    add(0.1, mac(A) + mac(B) + struct.pack("!HHH", 0x8100, (5 << 13) | 100, 0x0800) + inner)
    # IPv6 UDP
    v6src, v6dst = socket.inet_pton(socket.AF_INET6, "fe80::1"), socket.inet_pton(socket.AF_INET6, "ff02::1")
    u = udp(5353, 5353, b"mdns")
    add(0.1, eth("33:33:00:00:00:01", B, 0x86DD,
                 struct.pack("!IHBB", 0x60000000, len(u), 17, 255) + v6src + v6dst + u))
    # LLDP-like unknown ethertype
    add(0.1, eth("01:80:c2:00:00:0e", B, 0x88CC, b"\x02\x07\x04" + mac(B) + b"\x00" * 20))
    # ARP spoofing: a second MAC claims the gateway IP
    add(0.5, eth(A, "de:ad:be:ef:00:66", 0x0806, arp(2, "de:ad:be:ef:00:66", ipGW, A, ipA)))
    # Corrupted IPv4 checksum frame
    bad = bytearray(eth(GW, A, 0x0800, ipv4(ipA, ext, 17, udp(1111, 2222, b"corrupt"))))
    bad[24] ^= 0xFF
    add(0.1, bytes(bad))

    w = PcapWriter(path)
    for ts, f in frames:
        w.write(ts, f)
    w.close()
    print(f"wrote {len(frames)} frames to {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")
