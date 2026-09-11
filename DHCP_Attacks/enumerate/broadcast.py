#!/usr/bin/python3

from scapy.all import Ether, IP, UDP, sendp

IFACE = "wlan0"

print("[*] Sending UDP broadcast test packet to port 12345...")

pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
      IP(dst="255.255.255.255") / \
      UDP(sport=12345, dport=12345) / \
      b"This is a test broadcast message"

sendp(pkt, iface=IFACE, verbose=1)
