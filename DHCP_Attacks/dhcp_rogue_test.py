from scapy.all import AsyncSniffer, DHCP, BOOTP, Ether, IP, UDP, get_if_hwaddr, sendp
from time import sleep

INTERFACE = "wlan0"
SERVER_IP = "10.10.13.99"
OFFERED_IP = "10.10.13.199"
SUBNET_MASK = "255.255.255.0"
ROUTER_IP = "10.10.13.2"
DNS_IP = "10.10.13.53"


def handle_dhcp_packet(pkt):
    dhcp_options = pkt[DHCP].options
    op_type = next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 'message-type'), None)

    # DHCP_DISCOVER
    if op_type == 1:
        client_mac = pkt[Ether].src
        print(f"[*] Received DHCP Discover from {client_mac}")

        transaction_id = pkt[BOOTP].xid
        chaddr = pkt[BOOTP].chaddr
        server_mac = get_if_hwaddr(INTERFACE)

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

    # DHCP_REQUEST
    elif op_type == 3:
        return
        client_mac = pkt[Ether].src

        transaction_id = pkt[BOOTP].xid
        chaddr = pkt[BOOTP].chaddr
        server_mac = get_if_hwaddr(INTERFACE)

        requested_server = next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 'server_id'), None)
        requested_ip = next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 'requested_addr'), None)

        if requested_server and requested_server != SERVER_IP:
            print(f"[-] Client {client_mac} accepted offer from different server ({requested_server}). Ignoring.")
            return

        print(f"\n[*] Received DHCP Request from {client_mac} for IP {requested_ip or OFFERED_IP}")

        # CRAFT DHCP ACK
        eth = Ether(src=server_mac, dst=client_mac)
        ip = IP(src=SERVER_IP, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, yiaddr=OFFERED_IP, siaddr=SERVER_IP, chaddr=chaddr, xid=transaction_id)
        dhcp = DHCP(options=[
            ('message-type', 'ack'),
            ('server_id', SERVER_IP),
            ('subnet_mask', SUBNET_MASK),
            ('router', ROUTER_IP),
            ('name_server', DNS_IP),
            ('lease_time', 86400),
            'end'
        ])

        ack_packet = eth / ip / udp / bootp / dhcp
        print(f"[*] Sending DHCP ACK for {OFFERED_IP} to {client_mac}")
        sendp(ack_packet, iface=INTERFACE, verbose=False)


if __name__ == "__main__":
    print(f"[*] Listening for DHCP Discover packets on {INTERFACE}...")
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter="udp and (port 67 or 68)",
        prn=handle_dhcp_packet,
        store=0
    )

    sniffer.start()

    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
        print("[*] Sniffer stopped gracefully. Exiting.")
