/*
 * Userspace half of the XDP backend: loads xdp_firewall.bpf.o, attaches it to
 * the interface, mirrors the rule table into BPF maps, and pumps decisions
 * back out of the ring buffer into the shared log and statistics.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_filter.h"
#include "../xdp/xdp_shared.h"

/* The kernel program reuses fw_action_t's numbering; make sure it stays true. */
_Static_assert((int)ACTION_ALLOW      == (int)XACT_ALLOW,      "action ABI drift");
_Static_assert((int)ACTION_BLOCK      == (int)XACT_BLOCK,      "action ABI drift");
_Static_assert((int)ACTION_LOG_ONLY   == (int)XACT_LOG_ONLY,   "action ABI drift");
_Static_assert((int)ACTION_RATE_LIMIT == (int)XACT_RATE_LIMIT, "action ABI drift");

static const char *const bpf_object_paths[] = {
    "xdp/xdp_firewall.bpf.o",
    "./xdp_firewall.bpf.o",
    "/usr/local/share/flamewall/xdp_firewall.bpf.o",
    "/usr/share/flamewall/xdp_firewall.bpf.o",
    NULL
};

static struct {
    struct bpf_object  *obj;
    struct ring_buffer *rb;
    int rules_fd;
    int config_fd;
    int stats_fd;
    int ifindex;
    __u32 attach_flags;
    bool attached;

    pthread_t poll_thread;
    bool poll_thread_valid;

    struct xdp_stats *percpu;   /* scratch for reading the per-CPU stats map */
    int ncpu;

    time_t boot_wall;           /* wall clock at monotonic zero */
    unsigned synced_generation;

    firewall_ctx_t *ctx;
} st;

static char status_buf[512] = "XDP engine has not been started.";
static char libbpf_last_err[256];

static void set_status(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(status_buf, sizeof(status_buf), fmt, ap);
    va_end(ap);
}

const char *xdp_engine_status(void)
{
    return status_buf;
}

/* Keep libbpf's diagnostics - the verifier log in particular - so a failure
 * can say something more useful than "load failed". */
static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBBPF_WARN)
        vsnprintf(libbpf_last_err, sizeof(libbpf_last_err), fmt, ap);
    if (level != LIBBPF_DEBUG)
        vfprintf(stderr, fmt, ap);
    return 0;
}

static const char *find_bpf_object(void)
{
    for (int i = 0; bpf_object_paths[i]; i++) {
        if (access(bpf_object_paths[i], R_OK) == 0)
            return bpf_object_paths[i];
    }
    return NULL;
}

bool xdp_engine_available(void)
{
    return find_bpf_object() != NULL;
}

/* ---------- rule translation ---------- */

/* Returns the xdp_rule_kind for a FlameWall rule, or XR_NONE when the kernel
 * cannot evaluate it. */
static __u8 kind_for(rule_type_t t)
{
    switch (t) {
        case RULE_MAC_SRC:    return XR_MAC_SRC;
        case RULE_MAC_DST:    return XR_MAC_DST;
        case RULE_IP_SRC:     return XR_IP_SRC;
        case RULE_IP_DST:     return XR_IP_DST;
        case RULE_IP_RANGE:   return XR_IP_RANGE;
        case RULE_PORT_SRC:   return XR_PORT_SRC;
        case RULE_PORT_DST:   return XR_PORT_DST;
        case RULE_PORT_RANGE: return XR_PORT_RANGE;
        case RULE_PROTOCOL:   return XR_PROTOCOL;
        case RULE_ETHERTYPE:  return XR_ETHERTYPE;
        case RULE_RATE_LIMIT: return XR_RATE_LIMIT;
        default:              return XR_NONE;   /* DPI, GeoIP */
    }
}

/* Mirror the rule table into the BPF array map, preserving priority order.
 * Reports how many rules could not be offloaded. */
static int sync_rules(firewall_ctx_t *ctx, int *out_offloaded, int *out_skipped,
                      int *out_truncated)
{
    struct xdp_rule slot;
    int offloaded = 0, skipped = 0, truncated = 0;

    pthread_mutex_lock(&ctx->rules_lock);
    unsigned generation = ctx->rules_generation;

    for (int i = 0; i < ctx->rule_count; i++) {
        fw_rule_t *r = &ctx->rules[i];
        __u8 kind = kind_for(r->type);

        if (kind == XR_NONE) {
            skipped++;
            continue;
        }
        if (offloaded >= XDP_MAX_RULES) {
            truncated++;
            continue;
        }

        memset(&slot, 0, sizeof(slot));
        slot.id        = r->id;
        slot.enabled   = r->enabled ? 1 : 0;
        slot.kind      = kind;
        slot.action    = (__u8)r->action;
        slot.protocol  = r->protocol;
        slot.port      = r->port;
        slot.port_end  = r->port_end;
        slot.ethertype = r->ethertype;
        slot.ip        = r->ip;
        slot.ip_mask   = r->ip_mask;
        slot.ip_end    = r->ip_end;
        slot.max_pps   = (__u32)(r->max_packets_per_sec > 0 ? r->max_packets_per_sec : 0);
        slot.max_bps   = (__u32)(r->max_bytes_per_sec > 0 ? r->max_bytes_per_sec : 0);
        memcpy(slot.mac, r->mac, 6);

        __u32 key = (__u32)offloaded;
        if (bpf_map_update_elem(st.rules_fd, &key, &slot, BPF_ANY) != 0) {
            pthread_mutex_unlock(&ctx->rules_lock);
            return -1;
        }
        offloaded++;
    }

    fw_action_t policy = ctx->default_policy;
    pthread_mutex_unlock(&ctx->rules_lock);

    struct xdp_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.rule_count = (__u32)offloaded;
    cfg.default_action = (__u8)policy;
    cfg.log_all = 1;   /* the Monitor page expects to see allowed traffic too */

    __u32 zero = 0;
    if (bpf_map_update_elem(st.config_fd, &zero, &cfg, BPF_ANY) != 0)
        return -1;

    st.synced_generation = generation;

    if (out_offloaded) *out_offloaded = offloaded;
    if (out_skipped)   *out_skipped = skipped;
    if (out_truncated) *out_truncated = truncated;
    return 0;
}

/* ---------- statistics ---------- */

static void sync_stats(firewall_ctx_t *ctx)
{
    __u32 zero = 0;

    if (!st.percpu)
        return;
    if (bpf_map_lookup_elem(st.stats_fd, &zero, st.percpu) != 0)
        return;

    struct xdp_stats sum;
    memset(&sum, 0, sizeof(sum));

    for (int c = 0; c < st.ncpu; c++) {
        sum.total_packets += st.percpu[c].total_packets;
        sum.total_bytes   += st.percpu[c].total_bytes;
        sum.allowed       += st.percpu[c].allowed;
        sum.blocked       += st.percpu[c].blocked;
        sum.rate_limited  += st.percpu[c].rate_limited;
        sum.tcp           += st.percpu[c].tcp;
        sum.udp           += st.percpu[c].udp;
        sum.icmp          += st.percpu[c].icmp;
        sum.arp           += st.percpu[c].arp;
        sum.other         += st.percpu[c].other;
        sum.events_lost   += st.percpu[c].events_lost;
    }

    pthread_mutex_lock(&ctx->stats_lock);
    time_t start = ctx->stats.start_time;

    ctx->stats.total_packets = sum.total_packets;
    ctx->stats.total_bytes   = sum.total_bytes;
    ctx->stats.allowed       = sum.allowed;
    ctx->stats.blocked       = sum.blocked;
    ctx->stats.rate_limited  = sum.rate_limited;
    ctx->stats.tcp_count     = sum.tcp;
    ctx->stats.udp_count     = sum.udp;
    ctx->stats.icmp_count    = sum.icmp;
    ctx->stats.arp_count     = sum.arp;
    ctx->stats.other_count   = sum.other;

    time_t now = time(NULL);
    time_t elapsed = now - start;
    if (elapsed > 0) {
        ctx->stats.packets_per_second = (double)sum.total_packets / elapsed;
        ctx->stats.bytes_per_second   = (double)sum.total_bytes / elapsed;
    }
    ctx->stats.last_update = now;
    ctx->stats.start_time = start;
    pthread_mutex_unlock(&ctx->stats_lock);
}

/* ---------- event pump ---------- */

static int on_event(void *vctx, void *data, size_t len)
{
    firewall_ctx_t *ctx = (firewall_ctx_t *)vctx;
    const struct xdp_event *e = data;

    if (len < sizeof(*e))
        return 0;

    packet_info_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    memcpy(pkt.src_mac, e->src_mac, 6);
    memcpy(pkt.dst_mac, e->dst_mac, 6);
    pkt.ethertype = e->ethertype;
    pkt.src_ip    = e->src_ip;
    pkt.dst_ip    = e->dst_ip;
    pkt.protocol  = e->protocol;
    pkt.has_ip    = e->has_ip != 0;
    pkt.src_port  = e->src_port;
    pkt.dst_port  = e->dst_port;
    pkt.total_len = (int)e->pkt_len;
    pkt.direction = DIR_INBOUND;   /* XDP only sees ingress */
    pkt.timestamp = st.boot_wall + (time_t)(e->ts_ns / 1000000000ULL);

    /* Counters come straight from the BPF stats map, so only log here. */
    fw_log(ctx, &pkt, (fw_action_t)e->action, e->rule_id);
    return 0;
}

static void *xdp_poll_thread(void *arg)
{
    firewall_ctx_t *ctx = (firewall_ctx_t *)arg;
    time_t last_housekeeping = 0;

    while (ctx->running) {
        int n = ring_buffer__poll(st.rb, 200);
        if (n < 0 && n != -EINTR)
            break;

        time_t now = time(NULL);
        if (now != last_housekeeping) {
            last_housekeeping = now;
            sync_stats(ctx);

            /* Pick up rules added, removed or toggled in the GUI. */
            pthread_mutex_lock(&ctx->rules_lock);
            unsigned generation = ctx->rules_generation;
            pthread_mutex_unlock(&ctx->rules_lock);

            if (generation != st.synced_generation)
                sync_rules(ctx, NULL, NULL, NULL);
        }
    }
    return NULL;
}

/* ---------- lifecycle ---------- */

static void cleanup(void)
{
    if (st.attached) {
        bpf_xdp_detach(st.ifindex, st.attach_flags, NULL);
        st.attached = false;
    }
    if (st.rb) {
        ring_buffer__free(st.rb);
        st.rb = NULL;
    }
    if (st.obj) {
        bpf_object__close(st.obj);
        st.obj = NULL;
    }
    free(st.percpu);
    st.percpu = NULL;
}

int xdp_engine_start(firewall_ctx_t *ctx)
{
    memset(&st, 0, sizeof(st));
    st.ctx = ctx;
    libbpf_last_err[0] = '\0';

    if (geteuid() != 0) {
        set_status("Loading an XDP program needs root (CAP_BPF and CAP_NET_ADMIN).");
        return -1;
    }

    const char *path = find_bpf_object();
    if (!path) {
        set_status("xdp_firewall.bpf.o not found. Build it with: make xdp "
                   "(needs clang and libbpf-dev).");
        return -1;
    }

    st.ifindex = (int)if_nametoindex(ctx->interface);
    if (st.ifindex == 0) {
        set_status("No such interface: %s", ctx->interface);
        return -1;
    }

    libbpf_set_print(libbpf_print);

    /* Harmless on kernels that account BPF memory to the cgroup instead. */
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &r);

    st.obj = bpf_object__open_file(path, NULL);
    if (!st.obj) {
        set_status("Could not open %s: %s", path, strerror(errno));
        return -1;
    }

    if (bpf_object__load(st.obj) != 0) {
        set_status("The kernel rejected the BPF program: %s%s",
                   strerror(errno),
                   libbpf_last_err[0] ? " - see the terminal for the verifier log" : "");
        cleanup();
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(st.obj, "flamewall_xdp");
    struct bpf_map *rules  = bpf_object__find_map_by_name(st.obj, "fw_rules");
    struct bpf_map *config = bpf_object__find_map_by_name(st.obj, "fw_config");
    struct bpf_map *stats  = bpf_object__find_map_by_name(st.obj, "fw_stats");
    struct bpf_map *events = bpf_object__find_map_by_name(st.obj, "fw_events");

    if (!prog || !rules || !config || !stats || !events) {
        set_status("%s is missing the expected program or maps - rebuild it with make xdp.",
                   path);
        cleanup();
        return -1;
    }

    st.rules_fd  = bpf_map__fd(rules);
    st.config_fd = bpf_map__fd(config);
    st.stats_fd  = bpf_map__fd(stats);

    st.ncpu = libbpf_num_possible_cpus();
    if (st.ncpu <= 0) st.ncpu = 1;
    st.percpu = calloc(st.ncpu, sizeof(struct xdp_stats));
    if (!st.percpu) {
        set_status("Out of memory");
        cleanup();
        return -1;
    }

    int offloaded = 0, skipped = 0, truncated = 0;
    if (sync_rules(ctx, &offloaded, &skipped, &truncated) != 0) {
        set_status("Could not write the rule table into the BPF maps: %s",
                   strerror(errno));
        cleanup();
        return -1;
    }

    /* Native (driver) mode first; fall back to the generic SKB hook, which
     * works on any driver but runs later and slower. */
    int prog_fd = bpf_program__fd(prog);
    const char *mode = "native";

    st.attach_flags = XDP_FLAGS_DRV_MODE;
    int err = bpf_xdp_attach(st.ifindex, prog_fd, st.attach_flags, NULL);
    if (err) {
        st.attach_flags = XDP_FLAGS_SKB_MODE;
        mode = "generic";
        err = bpf_xdp_attach(st.ifindex, prog_fd, st.attach_flags, NULL);
    }
    if (err) {
        if (err == -EBUSY)
            set_status("%s already has an XDP program attached. Remove it with: "
                       "sudo ip link set dev %s xdp off", ctx->interface, ctx->interface);
        else
            set_status("Could not attach to %s: %s", ctx->interface, strerror(-err));
        cleanup();
        return -1;
    }
    st.attached = true;

    st.rb = ring_buffer__new(bpf_map__fd(events), on_event, ctx, NULL);
    if (!st.rb) {
        set_status("Could not open the event ring buffer: %s", strerror(errno));
        cleanup();
        return -1;
    }

    struct timespec mono, real;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &real);
    st.boot_wall = real.tv_sec - mono.tv_sec;

    ctx->engine = ENGINE_XDP;
    ctx->running = true;

    if (pthread_create(&st.poll_thread, NULL, xdp_poll_thread, ctx) != 0) {
        set_status("Could not start the event thread: %s", strerror(errno));
        ctx->running = false;
        cleanup();
        return -1;
    }
    st.poll_thread_valid = true;

    char note[256] = "";
    if (skipped > 0)
        snprintf(note, sizeof(note),
                 "  %d DPI rule%s stayed in userspace and %s NOT enforced here - "
                 "BPF has no regex engine.",
                 skipped, skipped == 1 ? "" : "s", skipped == 1 ? "is" : "are");
    if (truncated > 0)
        snprintf(note + strlen(note), sizeof(note) - strlen(note),
                 "  %d rule%s past the %d-rule kernel limit %s dropped.",
                 truncated, truncated == 1 ? "" : "s", XDP_MAX_RULES,
                 truncated == 1 ? "was" : "were");

    set_status("Attached to %s in %s mode. %d rule%s offloaded.%s"
               "  XDP filters inbound traffic only.",
               ctx->interface, mode, offloaded, offloaded == 1 ? "" : "s", note);
    return 0;
}

void xdp_engine_stop(firewall_ctx_t *ctx)
{
    ctx->running = false;

    if (st.poll_thread_valid) {
        pthread_join(st.poll_thread, NULL);
        st.poll_thread_valid = false;
    }

    /* One last read so the final counts are not lost with the maps. */
    if (st.percpu && st.stats_fd > 0)
        sync_stats(ctx);

    cleanup();
    set_status("XDP engine stopped and detached from %s.", ctx->interface);
}
