#!/usr/bin/env python3
from scapy.all import *
import random

# Random subdomain of example.com -> guaranteed cache miss, so the
# local DNS server MUST send out recursive queries. This is also the
# kind of query the Kaminsky attack needs later.
name = str(random.randint(0, 99999)) + ".example.com"

Qdsec = DNSQR(qname=name)

dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0,
          nscount=0, arcount=0, qd=Qdsec)

# dst: local DNS server, src: attacker
ip  = IP(dst='10.9.0.10', src='10.0.2.15')  
udp = UDP(dport=53, sport=33333, chksum=0)   

request = ip/udp/dns
send(request)
print("Sent query for:", name)