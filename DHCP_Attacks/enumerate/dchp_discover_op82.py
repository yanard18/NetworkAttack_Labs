#!/usr/bin/python3

from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC
import random

IFACE = "Ethernet 2"
FAKE_MAC = RandMAC()
XID = random.randint(1, 0xffffffff)

# Craft Option 82 (Relay Agent Info) with fake Circuit ID
# Format: (82, b'\x01\x04\x00\x00\x00\x01')  # Agent Circuit ID sub-option
option82 = b'\x01\x04\x00\x00\x00\x01'  # Sub-option 1 (Circuit ID), length 4, value

pkt = Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff") / \
      IP(src="0.0.0.0", dst="255.255.255.255") / \
      UDP(sport=68, dport=67) / \
      BOOTP(op=1, chaddr=FAKE_MAC, xid=XID) / \
      DHCP(options=[("message-type", "discover"),
                    (82, option82),  # <-- Option 82 spoofed
                    ('end')])

sendp(pkt, iface=IFACE, verbose=1)
print("[*] DHCPDISCOVER with spoofed Option 82 sent!")
