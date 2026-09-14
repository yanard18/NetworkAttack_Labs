#!/usr/bin/env python3
"""
prepare_packets.py

Builds two raw Ethernet frames (DHCP OFFER and DHCP ACK) with placeholder
fields that the C side will patch at runtime.

Run once (or whenever you change the server IP / offered IP / options):
    python3 prepare_packets.py
"""

from scapy.all import Ether, IP, UDP, BOOTP, DHCP

# --- configuration (must match the C side) ---
SERVER_IP   = "10.10.99.99" # any free ip
OFFERED_IP  = "10.10.99.101" # an IP not in the REAL POOL
SUBNET_MASK = "255.255.0.0"
ROUTER_IP   = "10.10.13.48"
DNS_IP      = "8.8.8.8"
LEASE_TIME  = 86400

# Offsets in the final frame (see C code for explanation)
OFF_UDP_CHKSUM = 40   # 14 (Eth) + 20 (IP) + 6 (UDP chksum field offset)


def build(msg_type: str) -> bytes:
    eth   = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")
    ip    = IP(src=SERVER_IP, dst="255.255.255.255")
    udp   = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2,
                  yiaddr=OFFERED_IP,
                  siaddr=SERVER_IP,
                  chaddr=b"\x00" * 16,   # patched per-client in C
                  xid=0)                 # patched per-client in C
    dhcp  = DHCP(options=[
        ('message-type', msg_type),
        ('server_id',    SERVER_IP),
        ('subnet_mask',  SUBNET_MASK),
        ('router',       ROUTER_IP),
        ('name_server',  DNS_IP),
        ('lease_time',   LEASE_TIME),
        'end',
    ])

    raw = bytearray(bytes(eth / ip / udp / bootp / dhcp))

    # Zero the UDP checksum (legal for IPv4) so we don't have to recompute
    # it in C after patching the payload.
    raw[OFF_UDP_CHKSUM]     = 0
    raw[OFF_UDP_CHKSUM + 1] = 0

    return bytes(raw)


def main() -> None:
    offer = build("offer")
    ack   = build("ack")

    with open("offer.bin", "wb") as f:
        f.write(offer)
    with open("ack.bin", "wb") as f:
        f.write(ack)

    print(f"offer.bin : {len(offer):4d} bytes")
    print(f"ack.bin   : {len(ack):4d} bytes")


if __name__ == "__main__":
    main()
