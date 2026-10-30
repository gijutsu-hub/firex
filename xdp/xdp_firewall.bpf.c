// SPDX-License-Identifier: GPL-2.0
/*
 * FlameWall XDP data path.
 *
 * Attached to an interface's ingress hook, so it sees inbound traffic only.
 * Rules arrive from userspace through fw_rules/fw_config; decisions are
 * counted in fw_stats and reported for the log view through fw_events.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_shared.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, XDP_MAX_RULES);
    __type(key, __u32);
    __type(value, struct xdp_rule);
} fw_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config);
} fw_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} fw_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, XDP_RATE_ENTRIES);
    __type(key, __u32);
    __type(value, struct xdp_rate_state);
} fw_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, XDP_EVENT_RINGBUF);
} fw_events SEC(".maps");

/* What we managed to pull out of the frame. */
struct parsed {
    __u8  src_mac[6];
    __u8  dst_mac[6];
    __u16 ethertype;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  has_ip;
};

static __always_inline int rate_exceeded(__u32 ip, __u32 len,
                                         __u32 max_pps, __u32 max_bps)
{
    __u64 now = bpf_ktime_get_ns();
    struct xdp_rate_state *st = bpf_map_lookup_elem(&fw_rate, &ip);

    if (!st) {
        struct xdp_rate_state init = {
            .window_start_ns = now,
            .packets = 1,
            .bytes = len,
        };
        bpf_map_update_elem(&fw_rate, &ip, &init, BPF_ANY);
        /* First packet of a new window cannot be over budget. */
        return 0;
    }

    if (now - st->window_start_ns >= XDP_RATE_WINDOW_NS) {
        st->window_start_ns = now;
        st->packets = 0;
        st->bytes = 0;
    }

    __sync_fetch_and_add(&st->packets, 1);
    __sync_fetch_and_add(&st->bytes, len);

    if (max_pps && st->packets > max_pps)
        return 1;
    if (max_bps && st->bytes > max_bps)
        return 1;
    return 0;
}

static __always_inline int rule_matches(struct xdp_rule *r, struct parsed *p,
                                        __u32 pkt_len)
{
    switch (r->kind) {
    case XR_MAC_SRC:
        return __builtin_memcmp(p->src_mac, r->mac, 6) == 0;
    case XR_MAC_DST:
        return __builtin_memcmp(p->dst_mac, r->mac, 6) == 0;
    case XR_IP_SRC:
        if (!p->has_ip)
            return 0;
        if (r->ip_mask)
            return (p->src_ip & r->ip_mask) == (r->ip & r->ip_mask);
        return p->src_ip == r->ip;
    case XR_IP_DST:
        if (!p->has_ip)
            return 0;
        if (r->ip_mask)
            return (p->dst_ip & r->ip_mask) == (r->ip & r->ip_mask);
        return p->dst_ip == r->ip;
    case XR_IP_RANGE: {
        if (!p->has_ip)
            return 0;
        __u32 a = bpf_ntohl(p->src_ip);
        return a >= bpf_ntohl(r->ip) && a <= bpf_ntohl(r->ip_end);
    }
    case XR_PORT_SRC:
        return p->has_ip && p->src_port == r->port;
    case XR_PORT_DST:
        return p->has_ip && p->dst_port == r->port;
    case XR_PORT_RANGE:
        if (!p->has_ip)
            return 0;
        return (p->dst_port >= r->port && p->dst_port <= r->port_end) ||
               (p->src_port >= r->port && p->src_port <= r->port_end);
    case XR_PROTOCOL:
        return p->has_ip && p->protocol == r->protocol;
    case XR_ETHERTYPE:
        return p->ethertype == r->ethertype;
    case XR_RATE_LIMIT:
        if (!p->has_ip)
            return 0;
        /* ip == 0 means "every source"; otherwise scope it to one address. */
        if (r->ip && p->src_ip != r->ip)
            return 0;
        return rate_exceeded(p->src_ip, pkt_len, r->max_pps, r->max_bps);
    default:
        return 0;
    }
}

SEC("xdp")
int flamewall_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    struct xdp_stats *st = bpf_map_lookup_elem(&fw_stats, &zero);
    if (!st)
        return XDP_PASS;

    struct xdp_config *cfg = bpf_map_lookup_elem(&fw_config, &zero);
    if (!cfg)
        return XDP_PASS;

    struct parsed p = {};
    __u32 pkt_len = (__u32)(data_end - data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(p.dst_mac, eth->h_dest, 6);
    __builtin_memcpy(p.src_mac, eth->h_source, 6);

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *cursor = (void *)(eth + 1);

    /* Unwrap a single VLAN tag, otherwise tagged traffic would slip past
     * every L3/L4 rule without matching anything. */
    if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
        struct vlan_hdr {
            __be16 tci;
            __be16 encap_proto;
        } *vh = cursor;

        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        h_proto = bpf_ntohs(vh->encap_proto);
        cursor = (void *)(vh + 1);
    }

    p.ethertype = h_proto;

    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = cursor;

        if ((void *)(ip + 1) > data_end)
            goto decide;

        __u32 ihl = ip->ihl * 4;
        if (ihl < sizeof(*ip))
            goto decide;
        if ((void *)ip + ihl > data_end)
            goto decide;

        p.has_ip = 1;
        p.src_ip = ip->saddr;
        p.dst_ip = ip->daddr;
        p.protocol = ip->protocol;

        void *l4 = (void *)ip + ihl;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;

            if ((void *)(tcp + 1) <= data_end) {
                p.src_port = bpf_ntohs(tcp->source);
                p.dst_port = bpf_ntohs(tcp->dest);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4;

            if ((void *)(udp + 1) <= data_end) {
                p.src_port = bpf_ntohs(udp->source);
                p.dst_port = bpf_ntohs(udp->dest);
            }
        }
    }

decide:;
    __u8 action = cfg->default_action;
    __s32 matched = -1;

    __u32 count = cfg->rule_count;
    if (count > XDP_MAX_RULES)
        count = XDP_MAX_RULES;

    for (__u32 i = 0; i < XDP_MAX_RULES; i++) {
        if (i >= count)
            break;

        struct xdp_rule *r = bpf_map_lookup_elem(&fw_rules, &i);
        if (!r)
            break;
        if (!r->enabled || r->kind == XR_NONE)
            continue;

        if (rule_matches(r, &p, pkt_len)) {
            matched = r->id;
            action = r->action;
            break;
        }
    }

    /* Counters */
    st->total_packets++;
    st->total_bytes += pkt_len;

    if (p.has_ip) {
        if (p.protocol == IPPROTO_TCP)
            st->tcp++;
        else if (p.protocol == IPPROTO_UDP)
            st->udp++;
        else if (p.protocol == IPPROTO_ICMP)
            st->icmp++;
        else
            st->other++;
    } else if (p.ethertype == ETH_P_ARP) {
        st->arp++;
    } else {
        st->other++;
    }

    int drop = (action == XACT_BLOCK || action == XACT_RATE_LIMIT);

    if (action == XACT_RATE_LIMIT)
        st->rate_limited++;
    if (drop)
        st->blocked++;
    else
        st->allowed++;

    /* Report the decision. Unmatched packets are only reported when the
     * loader asks for it, so a busy link does not drown the ring buffer. */
    if (matched >= 0 || cfg->log_all) {
        struct xdp_event *e = bpf_ringbuf_reserve(&fw_events, sizeof(*e), 0);

        if (e) {
            e->ts_ns = bpf_ktime_get_ns();
            e->src_ip = p.src_ip;
            e->dst_ip = p.dst_ip;
            e->pkt_len = pkt_len;
            e->rule_id = matched;
            e->src_port = p.src_port;
            e->dst_port = p.dst_port;
            e->ethertype = p.ethertype;
            e->protocol = p.protocol;
            e->action = action;
            e->has_ip = p.has_ip;
            e->_pad[0] = 0;
            e->_pad[1] = 0;
            e->_pad[2] = 0;
            __builtin_memcpy(e->src_mac, p.src_mac, 6);
            __builtin_memcpy(e->dst_mac, p.dst_mac, 6);
            bpf_ringbuf_submit(e, 0);
        } else {
            st->events_lost++;
        }
    }

    return drop ? XDP_DROP : XDP_PASS;
}
