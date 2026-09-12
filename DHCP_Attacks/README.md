# DORA Process Briefly

The DHCP **DORA** process is the four-step sequence a device (client) uses to automatically obtain an IP address from a network server:

1. **Discover:** The client broadcasts a message to the network asking, "Are there any DHCP servers out there?"
2. **Offer:** A DHCP server replies with a proposed IP address ("Here is an IP you can use.").
3. **Request:** The client formally requests the offered IP, letting the server (and any other listening servers) know it accepted the offer ("I will take that IP.").
4. **Acknowledge:** The server confirms the lease and sends final network settings like the subnet mask and default gateway ("It's yours, here is your configuration.").

# Enumerate Network

1. First perform UDP broadcast, and analyze if packet received
2. Perform DHCP_DISCOVER broadcast, and analyze if packet received
3. Perform DHCP_DISCOVER unicast, and analyze if packet received

If UDP Broadcast passed, but DCHP_DISCOVER is blocked, this is **DHCP Snooping** - a security feature that blocks DHCP messages on untrusted ports. The switch sees the `BOOTP` header and the `DHCP` options inside the UDP payload, recognize it as DCHP packet, and drops it intentionally. 

## Bypass DCHP Snooping

1. DHCP Snooping is usually configured to only filter broadcast DHCP packets, assuming that DHCP must always start with a broadcast Discover.
2. Tools like Yersinia, first scan the network then send Unicast Discover messages to its victims.
3. udp/67 and udp/68 blocked by DHCP Snooping
4. Perform all tests both on Wi-Fi and Ethernet.

Victim device use DCHP client (ex: `dhclient`), to send DHCP_DISCOVER broadcast, however modem block the broadcast message. So we can not reply with a DHCP_OFFER.

## NAK

`NAK` packet reset the DORA process

To bypass:
- Offer an IP that the real server won't contest
- Impersonate the real server's `server_id` (DHCP server's IP).
- Be fast
