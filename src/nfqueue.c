#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <net/if.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "nfqueue.h"
#include "dpi.h"
#include "ratelimit.h"

// The interface name reaches us from a GUI text entry and ends up inside a
// root `system()` call, so only accept the characters a real ifname can hold.
static bool iface_name_is_safe(const char *iface) {
    if (!iface || !iface[0]) return false;
    if (strlen(iface) >= MAX_IFACE_NAME) return false;
    for (const char *p = iface; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
            return false;
    }
    return true;
}

static int fw_nfq_handle_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                        struct nfq_data *nfa, void *data) {
    (void)nfmsg;
    firewall_ctx_t *ctx = (firewall_ctx_t *)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return -1;

    uint32_t id = ntohl(ph->packet_id);

    unsigned char *payload_data = NULL;
    int len = nfq_get_payload(nfa, &payload_data);
    if (len < 0 || !payload_data) {
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }

    // NFQUEUE hands us Layer 3 and up - there is no Ethernet header here.
    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.total_len = len;
    pkt.timestamp = time(NULL);
    pkt.ethertype = 0x0800; // IPv4

    if (len >= 20) {
        struct iphdr *ip = (struct iphdr *)payload_data;
        int ip_hdr_len = ip->ihl * 4;

        if (ip->version == 4 && ip_hdr_len >= 20 && ip_hdr_len <= len) {
            pkt.src_ip = ip->saddr;
            pkt.dst_ip = ip->daddr;
            pkt.protocol = ip->protocol;
            pkt.ttl = ip->ttl;
            pkt.has_ip = true;

            if (pkt.protocol == IPPROTO_TCP && len >= ip_hdr_len + 20) {
                struct tcphdr *tcp = (struct tcphdr*)(payload_data + ip_hdr_len);
                pkt.src_port = ntohs(tcp->source);
                pkt.dst_port = ntohs(tcp->dest);
                pkt.tcp_flags = ((unsigned char*)tcp)[13];
                int tcp_hdr_len = tcp->doff * 4;
                if (tcp_hdr_len >= 20 && len > ip_hdr_len + tcp_hdr_len) {
                    pkt.payload = payload_data + ip_hdr_len + tcp_hdr_len;
                    pkt.payload_len = len - ip_hdr_len - tcp_hdr_len;
                }
            } else if (pkt.protocol == IPPROTO_UDP && len >= ip_hdr_len + 8) {
                struct udphdr *udp = (struct udphdr*)(payload_data + ip_hdr_len);
                pkt.src_port = ntohs(udp->source);
                pkt.dst_port = ntohs(udp->dest);
                if (len > ip_hdr_len + 8) {
                    pkt.payload = payload_data + ip_hdr_len + 8;
                    pkt.payload_len = len - ip_hdr_len - 8;
                }
            }
        }
    }

    /* NFQUEUE hands us the ingress ifindex; the VLAN tag is already stripped
     * by the kernel, so segmentation here keys off the sub-interface name
     * (eth1.10) rather than an 802.1Q header. */
    char indev[IFNAMSIZ] = "";
    unsigned idx = nfq_get_indev(nfa);
    if (idx) if_indextoname(idx, indev);
    snprintf(pkt.ingress_if, MAX_IFACE_NAME, "%s", indev[0] ? indev : ctx->interface);

    int matched_rule = -1;
    fw_action_t action = ctx->inspect_hook
        ? ctx->inspect_hook(ctx, &pkt, pkt.ingress_if, &matched_rule)
        : fw_check_packet(ctx, &pkt, &matched_rule);

    update_stats(ctx, &pkt, action);
    fw_log(ctx, &pkt, action, matched_rule);

    // VERDICT: Accept or Drop. RATE_LIMIT drops the packets over the budget,
    // which is what the rule matched on in the first place.
    uint32_t verdict = (action == ACTION_BLOCK || action == ACTION_RATE_LIMIT)
                       ? NF_DROP : NF_ACCEPT;
    nfq_set_verdict(qh, id, verdict, 0, NULL);

    return 0;
}

int nfq_setup_iptables(const char *iface, int queue_num) {
    if (!iface_name_is_safe(iface)) {
        fprintf(stderr, "nfqueue: refusing to use interface name \"%s\"\n",
                iface ? iface : "(null)");
        return -1;
    }

    static const char *chains[3] = {"INPUT", "OUTPUT", "FORWARD"};
    static const char *flags[3]  = {"-i", "-o", "-i"};
    char cmd[256];

    for (int i = 0; i < 3; i++) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -I %s %s %s -j NFQUEUE --queue-num %d",
                 chains[i], flags[i], iface, queue_num);
        if (system(cmd) != 0)
            fprintf(stderr, "nfqueue: command failed: %s\n", cmd);
    }
    return 0;
}

int nfq_cleanup_iptables(const char *iface, int queue_num) {
    if (!iface_name_is_safe(iface)) return -1;

    static const char *chains[3] = {"INPUT", "OUTPUT", "FORWARD"};
    static const char *flags[3]  = {"-i", "-o", "-i"};
    char cmd[256];

    for (int i = 0; i < 3; i++) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -D %s %s %s -j NFQUEUE --queue-num %d",
                 chains[i], flags[i], iface, queue_num);
        if (system(cmd) != 0)
            fprintf(stderr, "nfqueue: cleanup command failed: %s\n", cmd);
    }
    return 0;
}

static void *nfq_thread(void *arg) {
    firewall_ctx_t *ctx = (firewall_ctx_t *)arg;

    struct nfq_handle *h = nfq_open();
    if (!h) {
        perror("nfq_open");
        ctx->running = false;
        return NULL;
    }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf");
        nfq_close(h);
        ctx->running = false;
        return NULL;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, ctx->queue_num,
                                               &fw_nfq_handle_packet, ctx);
    if (!qh) {
        perror("nfq_create_queue");
        nfq_close(h);
        ctx->running = false;
        return NULL;
    }

    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_queue_maxlen(qh, 4096);

    int fd = nfq_fd(h);

    // Time out the read so a stop request is noticed on an idle queue.
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[65536] __attribute__((aligned));

    while (ctx->running) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
        if (errno == ENOBUFS) continue;  // kernel dropped some: keep going
        perror("nfq recv");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return NULL;
}

int nfq_engine_start(firewall_ctx_t *ctx) {
    if (!iface_name_is_safe(ctx->interface)) {
        fprintf(stderr, "nfqueue: invalid interface name\n");
        return -1;
    }

    if (nfq_setup_iptables(ctx->interface, ctx->queue_num) != 0)
        return -1;

    ctx->engine = ENGINE_NFQUEUE;
    ctx->running = true;

    if (pthread_create(&ctx->capture_thread, NULL, nfq_thread, ctx) != 0) {
        perror("pthread_create");
        ctx->running = false;
        nfq_cleanup_iptables(ctx->interface, ctx->queue_num);
        return -1;
    }
    ctx->capture_thread_valid = true;
    return 0;
}

void nfq_engine_stop(firewall_ctx_t *ctx) {
    ctx->running = false;
    if (ctx->capture_thread_valid) {
        pthread_join(ctx->capture_thread, NULL);
        ctx->capture_thread_valid = false;
    }
    nfq_cleanup_iptables(ctx->interface, ctx->queue_num);
}
