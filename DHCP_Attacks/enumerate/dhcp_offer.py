from scapy.all import *

SERVER_IP = "10.10.13.99"
SUBNET_MASK = "255.255.255.0"
ROUTER_IP = "10.10.13.2"
DNS_IP = "10.10.13.53"
OFFERED_IP = "10.10.13.199"

server_mac = "bc:17:b8:3f:ed:8c"
chaddr = "bc:17:b8:3f:ed:8c"
transaction_id = 0x0
INTERFACE = "wlan0"
client_mac = "48:e7:da:cc:10:ab"

# --- CRAFT the DHCP OFFER ---
eth = Ether(src=server_mac, dst=client_mac)
ip = IP(src=SERVER_IP, dst="255.255.255.255")
udp = UDP(sport=67, dport=68)
bootp = BOOTP(op=2, yiaddr=OFFERED_IP, siaddr=SERVER_IP, chaddr=chaddr, xid=transaction_id)
dhcp = DHCP(options=[
    ('message-type', 'offer'),
    ('server_id', SERVER_IP),
    ('subnet_mask', SUBNET_MASK),
    ('router', ROUTER_IP),
    ('name_server', DNS_IP),
    ('lease_time', 86400), # 1 day lease
    'end'
])

offer_pkt = eth / ip / udp / bootp / dhcp

print(f"[*] Sending DHCP Offer: {OFFERED_IP} to {client_mac}")

sendp(offer_pkt, iface=INTERFACE, verbose=False)