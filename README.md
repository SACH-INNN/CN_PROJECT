# Network Packet Monitoring and Ethernet Frame Analysis System

A pure-Python (standard library only, Python 3.8+) tool that captures or reads Ethernet
frames and decodes Ethernet II, 802.1Q VLAN, ARP, IPv4, IPv6, ICMP, TCP and UDP headers.
It prints a per-frame analysis, a traffic summary, and runs basic anomaly checks
(ARP spoofing, SYN floods, runt/oversize frames, bad IPv4 checksums).

## Files
- `packet_monitor.py` - the analyser (live capture + pcap reader)
- `generate_sample_pcap.py` - builds `sample.pcap`, a synthetic capture for testing
- `sample.pcap`, `sample_output.txt`, `frames.csv` - example input and output

## Usage
```bash
# Analyse a capture file (no root needed)
python3 packet_monitor.py -r sample.pcap
python3 packet_monitor.py -r sample.pcap --brief
python3 packet_monitor.py -r sample.pcap --hex -c 5
python3 packet_monitor.py -r sample.pcap -f "tcp,port=80" --csv frames.csv

# Live capture (Linux only, needs root)
sudo python3 packet_monitor.py -i eth0 -c 100
sudo python3 packet_monitor.py -i eth0 -t 30 -w capture.pcap   # also open in Wireshark
```

Options: `-i` interface, `-r` read pcap, `-w` write pcap, `-c` frame count, `-t` seconds,
`-f` filter (`tcp`, `udp`, `arp`, `icmp`, `ipv6`, `host=IP`, `port=N`, `mac=XX`; comma = AND),
`--hex`, `--brief`, `--csv FILE`, `--no-summary`.

## Notes
- Live capture uses `AF_PACKET` raw sockets, so it is Linux-only. On Windows/macOS use
  `-r` with a file saved from Wireshark/tcpdump (classic .pcap, Ethernet link type).
- Capture only on networks you own or are authorised to monitor.
- Checksum "mismatch" on frames captured on the sending host is usually NIC checksum
  offload, not corruption.
