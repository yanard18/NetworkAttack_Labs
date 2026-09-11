#!/usr/bin/python3
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC
import random

IFACE = "wlan0"
src_mac = "bc:17:b8:3f:ed:8c"
xid = random.randint(1, 0xffffffff)

print(f"[*] Sending Broadcast DHCPDISCOVER on {IFACE}...")

pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / \
      IP(src="0.0.0.0", dst="255.255.255.255") / \
      UDP(sport=68, dport=67) / \
      BOOTP(op=1, chaddr=src_mac, xid=xid) / \
      DHCP(options=[("message-type", "discover"), ('end')])

sendp(pkt, iface=IFACE, verbose=1)
print("[*] DHCPDISCOVER sent.")
