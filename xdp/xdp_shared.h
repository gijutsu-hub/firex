/*
 * ABI shared between the XDP kernel program and the userspace loader.
 * Both sides are built for the same 64-bit little-endian target, so the
 * structs below are laid out identically; keep the explicit padding in place
 * when adding fields.
 */
#ifndef FW_XDP_SHARED_H
#define FW_XDP_SHARED_H

#ifdef __BPF__
#include <linux/types.h>
#else
#include <linux/types.h>
#include <stdint.h>
#endif

/* The verifier has to walk this loop on every packet, so keep it modest. */
#define XDP_MAX_RULES       64
#define XDP_RATE_ENTRIES    10240
#define XDP_RATE_WINDOW_NS  1000000000ULL   /* 1 second */
#define XDP_EVENT_RINGBUF   (256 * 1024)

/* Rule kinds the kernel can evaluate. DPI (regex and literal content) is
 * deliberately absent: there is no regex engine in BPF, and scanning payloads
 * byte by byte does not survive the verifier's complexity limit. The loader
 * reports any such rule as not offloaded rather than dropping it silently. */
enum xdp_rule_kind {
    XR_NONE = 0,
    XR_MAC_SRC,
    XR_MAC_DST,
    XR_IP_SRC,
    XR_IP_DST,
    XR_IP_RANGE,
    XR_PORT_SRC,
    XR_PORT_DST,
    XR_PORT_RANGE,
    XR_PROTOCOL,
    XR_ETHERTYPE,
    XR_RATE_LIMIT,
};

/* Deliberately the same numbering as fw_action_t in firewall.h; the loader
 * asserts that they still line up. Named fw_xdp_action because linux/bpf.h
 * already owns the tag "xdp_action" for the XDP_PASS/XDP_DROP return codes. */
enum fw_xdp_action {
    XACT_ALLOW      = 0,
    XACT_BLOCK      = 1,
    XACT_LOG_ONLY   = 2,
    XACT_RATE_LIMIT = 3,
};

struct xdp_rule {
    __s32 id;
    __u8  enabled;
    __u8  kind;
    __u8  action;
    __u8  protocol;
    __u16 port;
    __u16 port_end;
    __u16 ethertype;
    __u16 _pad0;
    __u32 ip;
    __u32 ip_mask;
    __u32 ip_end;
    __u32 max_pps;
    __u32 max_bps;
    __u8  mac[6];
    __u8  _pad1[2];
};

struct xdp_config {
    __u32 rule_count;
    __u8  default_action;   /* enum fw_xdp_action */
    __u8  log_all;          /* 1 = emit an event for every packet */
    __u8  _pad[2];
};

struct xdp_stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 allowed;
    __u64 blocked;
    __u64 rate_limited;
    __u64 tcp;
    __u64 udp;
    __u64 icmp;
    __u64 arp;
    __u64 other;
    __u64 events_lost;
};

struct xdp_event {
    __u64 ts_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pkt_len;
    __s32 rule_id;
    __u16 src_port;
    __u16 dst_port;
    __u16 ethertype;
    __u8  protocol;
    __u8  action;           /* enum fw_xdp_action */
    __u8  has_ip;
    __u8  _pad[3];
    __u8  src_mac[6];
    __u8  dst_mac[6];
};

struct xdp_rate_state {
    __u64 window_start_ns;
    __u32 packets;
    __u32 bytes;
};

#endif /* FW_XDP_SHARED_H */
