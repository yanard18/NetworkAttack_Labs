#!/usr/bin/python3
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC

iface_input = "Ethernet 2"

fake_mac = RandMAC()
LINUX_MAC = "8c:47:be:4a:6f:23"

requested_ip = "192.168.1.20"
server_ip = "192.168.1.2"

broadcast = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")
unicast = Ether(src=fake_mac, dst=LINUX_MAC)


ip = IP(src="0.0.0.0", dst="255.255.255.255")
udp = UDP(sport=68, dport=67)
bootp = BOOTP(op=1, chaddr=fake_mac)

dhcp = DHCP(
    options=[("message-type", "request"),      # REQUEST type
             ("requested_addr", requested_ip), # The IP you want
             ("server_id", server_ip),         # Must match your modem's IP
             ('end')]
)

pkt = unicast / ip / udp / bootp / dhcp

sendp(pkt, iface=iface_input)
print(f"Sent REQUEST for {requested_ip} from MAC {fake_mac}")