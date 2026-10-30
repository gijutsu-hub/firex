/*
 * Gateway monitoring and multi-WAN failover. See include/gwmon.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "gwmon.h"
#include "egress.h"
#include "netutil.h"
#include "shellcmd.h"
#include "brand.h"

/* Identifies our own echoes in the reply stream. ICMP ping sockets rewrite
 * the id field, so the payload is what we actually match on. */
static const char PROBE_MAGIC[8] = { 'F','I','R','E','X','g','w','1' };

const char *gwmon_status_str(gw_status_t s) {
    switch (s) {
        case GW_UP:          return "up";
        case GW_DOWN:        return "down";
        case GW_UNMONITORED: return "unmonitored";
        default:             return "unknown";
    }
}

static uint16_t icmp_checksum(const void *buf, size_t len) {
    const uint16_t *w = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *w++; len -= 2; }
    if (len) sum += *(const uint8_t *)w;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static double ms_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (double)(t1.tv_sec - t0->tv_sec) * 1000.0 +
           (double)(t1.tv_nsec - t0->tv_nsec) / 1.0e6;
}

double gwmon_ping(const char *target, const char *ifname, int timeout_ms) {
    if (!target || !*target) return -1;

    /*
     * An ICMP echo is the appliance talking, so the air gap applies. The
     * consequence is deliberate and visible: while the gap is shut the WAN
     * pages show the link state as unknown rather than up, because nobody
     * asked. A monitor that kept pinging would be the appliance announcing
     * itself from a box the operator believes is silent.
     *
     * discover_gateway() below is NOT gated -- it reads the kernel's own
     * routing table and sends nothing.
     */
    if (!egress_permitted(EGRESS_GWMON, NULL, 0)) return -1;

    struct in_addr dst;
    if (inet_pton(AF_INET, target, &dst) != 1) return -1;

    /*
     * Prefer the unprivileged ICMP socket; it needs no CAP_NET_RAW when
     * net.ipv4.ping_group_range allows it, and behaves identically here.
     */
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    bool raw = false;
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        raw = true;
    }
    if (fd < 0) return -1;

    if (ifname && *ifname &&
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1) != 0) {
        /* Without CAP_NET_RAW this fails; the probe still works, it just is
         * not pinned to the link we meant to test. */
        static bool warned = false;
        if (!warned) {
            fprintf(stderr, "[%s] gateway monitor cannot bind probes to an "
                    "interface (%s); results are not per-link\n",
                    BRAND_PRODUCT, strerror(errno));
            warned = true;
        }
    }

    static uint16_t seq_counter;
    uint16_t seq = __atomic_add_fetch(&seq_counter, 1, __ATOMIC_RELAXED);

    struct {
        struct icmphdr hdr;
        char           payload[16];
    } pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.type             = ICMP_ECHO;
    pkt.hdr.code             = 0;
    pkt.hdr.un.echo.id       = htons((uint16_t)(getpid() & 0xffff));
    pkt.hdr.un.echo.sequence = htons(seq);
    memcpy(pkt.payload, PROBE_MAGIC, sizeof(PROBE_MAGIC));
    memcpy(pkt.payload + 8, &seq, sizeof(seq));
    pkt.hdr.checksum = icmp_checksum(&pkt, sizeof(pkt));

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr   = dst;

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        close(fd);
        return -1;
    }

    /* Replies from other pings can arrive on this socket, so read until one
     * carries our magic and sequence, or the budget runs out. */
    for (;;) {
        double spent = ms_since(&t0);
        int remain = timeout_ms - (int)spent;
        if (remain <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, remain);
        if (pr <= 0) break;

        unsigned char buf[256];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        /* A raw socket hands back the IP header; a ping socket does not. */
        size_t off = 0;
        if (raw) {
            if (n < 20) continue;
            off = (size_t)((buf[0] & 0x0f) * 4);
            if ((ssize_t)off + (ssize_t)sizeof(pkt) > n) continue;
        }
        if ((size_t)n < off + sizeof(struct icmphdr) + 16) continue;

        struct icmphdr *rh = (struct icmphdr *)(buf + off);
        if (rh->type != ICMP_ECHOREPLY) continue;

        const char *pl = (const char *)(buf + off + sizeof(struct icmphdr));
        if (memcmp(pl, PROBE_MAGIC, sizeof(PROBE_MAGIC)) != 0) continue;

        uint16_t got;
        memcpy(&got, pl + 8, sizeof(got));
        if (got != seq) continue;

        double rtt = ms_since(&t0);
        close(fd);
        return rtt;
    }

    close(fd);
    return -1;
}

/* Reads the gateway the kernel currently uses for this interface, so a DHCP
 * or PPPoE link can be restored after its default route is removed. */
static uint32_t discover_gateway(const char *ifname) {
    if (!ifname || !*ifname || !fx_ifname_safe(ifname, IFNAME_LEN)) return 0;

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ip -4 route show default dev %s 2>/dev/null", ifname);

    FILE *p = popen(cmd, "r");
    if (!p) return 0;

    char line[256];
    uint32_t gw = 0;
    while (fgets(line, sizeof(line), p)) {
        char *via = strstr(line, "via ");
        if (!via) continue;
        char addr[INET_ADDRSTRLEN] = "";
        if (sscanf(via + 4, "%45s", addr) != 1) continue;
        struct in_addr a;
        if (inet_pton(AF_INET, addr, &a) == 1) { gw = a.s_addr; break; }
    }
    pclose(p);
    return gw;
}

int gwmon_select(const wan_config_t *wan, const gw_state_t *st, int count) {
    int best = -1;

    for (int i = 0; i < count; i++) {
        if (wan[i].mode == WAN_DISABLED) continue;
        if (st[i].status == GW_DOWN)     continue;
        /* GW_UNKNOWN means it has not been probed yet. Treating it as usable
         * keeps the primary link carrying traffic through startup instead of
         * flapping to the backup for the first few seconds. */

        if (best < 0) { best = i; continue; }

        if (wan[i].failover_priority != wan[best].failover_priority) {
            if (wan[i].failover_priority < wan[best].failover_priority) best = i;
            continue;
        }
        /* Equal priority: a link flagged as backup yields to one that is not. */
        if (wan[best].is_backup && !wan[i].is_backup) best = i;
    }
    return best;
}

bool gwmon_record(gwmon_ctx_t *g, gw_state_t *s, bool ok, double rtt_ms) {
    s->probes++;
    s->last_probe = time(NULL);
    s->last_rtt_ms = ok ? rtt_ms : -1;

    if (!ok) s->failures++;

    s->window[s->window_idx] = ok ? 0 : 1;
    s->window_idx = (s->window_idx + 1) % GW_RTT_WINDOW;
    if (s->window_len < GW_RTT_WINDOW) s->window_len++;

    int lost = 0;
    for (int i = 0; i < s->window_len; i++) lost += s->window[i];
    s->loss_pct = s->window_len ? (lost * 100) / s->window_len : 0;

    if (ok) {
        /* Exponential average keeps one slow reply from dominating. */
        s->avg_rtt_ms = s->avg_rtt_ms > 0
            ? s->avg_rtt_ms * 0.8 + rtt_ms * 0.2
            : rtt_ms;
        s->consecutive_ok++;
        s->consecutive_fail = 0;
    } else {
        s->consecutive_fail++;
        s->consecutive_ok = 0;
    }

    gw_status_t was = s->status;

    if (s->status != GW_UP && s->consecutive_ok >= g->ok_threshold)
        s->status = GW_UP;
    else if (s->status != GW_DOWN && s->consecutive_fail >= g->fail_threshold)
        s->status = GW_DOWN;

    if (s->status != was) {
        s->last_change = time(NULL);
        return true;
    }
    return false;
}

/*
 * Rebuilds the default route set. The winning link gets the low metric; the
 * others keep their gateway but at a metric the kernel will never prefer, so
 * a recovery does not have to rediscover anything. A link that is down has
 * its default route removed entirely.
 */
static void apply_routes_locked(gwmon_ctx_t *g) {
    if (!g->apply_net) return;

    char cmd[512], gbuf[INET_ADDRSTRLEN];

    for (int i = 0; i < g->wan_count; i++) {
        wan_config_t *w  = &g->nc->wan[i];
        gw_state_t   *s  = &g->state[i];

        if (w->mode == WAN_DISABLED) continue;
        if (!fx_ifname_safe(w->ifname, IFNAME_LEN)) continue;

        uint32_t gw = w->mode == WAN_STATIC ? w->gateway : s->gateway;
        if (!gw) continue;          /* nothing learned yet; leave it be */

        fx_ip_str(gw, gbuf, sizeof(gbuf));

        if (s->status == GW_DOWN) {
            snprintf(cmd, sizeof(cmd),
                     "ip route del default via %s dev %s 2>/dev/null",
                     gbuf, w->ifname);
            fx_try(cmd);
            s->active = false;
            continue;
        }

        int metric = (i == g->active_wan)
            ? 100
            : 500 + w->failover_priority;

        snprintf(cmd, sizeof(cmd),
                 "ip route replace default via %s dev %s metric %d",
                 gbuf, w->ifname, metric);
        fx_run(cmd);
        s->active = (i == g->active_wan);
    }
}

/* Picks up tuning that a reload may have changed. Called once per round so
 * SIGHUP means something for the monitor and not just for the rule tables. */
static void refresh_tuning(gwmon_ctx_t *g) {
    netconf_ctx_t *n = g->nc;
    if (!n) return;

    int iv = n->monitor_interval   ? n->monitor_interval   : GW_DEFAULT_INTERVAL;
    int to = n->monitor_timeout_ms ? n->monitor_timeout_ms : GW_DEFAULT_TIMEOUT_MS;
    int fl = n->monitor_fail       ? n->monitor_fail       : GW_DEFAULT_FAIL;
    int okk = n->monitor_ok        ? n->monitor_ok         : GW_DEFAULT_OK;

    if (iv == g->interval_sec && to == g->timeout_ms &&
        fl == g->fail_threshold && okk == g->ok_threshold)
        return;

    printf("[%s] gateway monitor retuned: every %ds, timeout %dms, "
           "down after %d, up after %d\n", BRAND_PRODUCT, iv, to, fl, okk);
    g->interval_sec   = iv;
    g->timeout_ms     = to;
    g->fail_threshold = fl;
    g->ok_threshold   = okk;
}

static void *gw_thread(void *arg) {
    gwmon_ctx_t *g = arg;

    while (g->running) {
        pthread_mutex_lock(&g->lock);
        refresh_tuning(g);
        g->wan_count = g->nc->wan_count;
        pthread_mutex_unlock(&g->lock);

        for (int i = 0; i < g->wan_count && g->running; i++) {
            wan_config_t *w = &g->nc->wan[i];

            if (w->mode == WAN_DISABLED) continue;

            if (!w->monitor_ip[0]) {
                pthread_mutex_lock(&g->lock);
                g->state[i].status = GW_UNMONITORED;
                pthread_mutex_unlock(&g->lock);
                continue;
            }

            /* A changed monitor target means the previous results describe a
             * different thing; start that link's history over. */
            pthread_mutex_lock(&g->lock);
            if (strcmp(g->state[i].probing, w->monitor_ip) != 0) {
                gw_state_t *s0 = &g->state[i];
                snprintf(s0->probing, sizeof(s0->probing), "%s", w->monitor_ip);
                s0->consecutive_ok = s0->consecutive_fail = 0;
                s0->window_idx = s0->window_len = 0;
                s0->avg_rtt_ms = 0;
                s0->status = GW_UNKNOWN;
            }
            pthread_mutex_unlock(&g->lock);

            double rtt = gwmon_ping(w->monitor_ip, w->ifname, g->timeout_ms);

            pthread_mutex_lock(&g->lock);
            gw_state_t *s = &g->state[i];

            /* Learn the gateway for links that get one from the network. */
            if (w->mode != WAN_STATIC && !s->gateway)
                s->gateway = discover_gateway(w->ifname);

            bool changed = gwmon_record(g, s, rtt >= 0, rtt);

            if (changed) {
                printf("[%s] WAN%d (%s) is %s  rtt=%.1fms loss=%d%%\n",
                       BRAND_PRODUCT, i, w->ifname,
                       gwmon_status_str(s->status),
                       s->avg_rtt_ms, s->loss_pct);

                int sel = gwmon_select(g->nc->wan, g->state, g->wan_count);
                if (sel != g->active_wan) {
                    int prev = g->active_wan;
                    g->active_wan = sel;

                    if (sel >= 0)
                        printf("[%s] FAILOVER: default route -> WAN%d (%s)\n",
                               BRAND_PRODUCT, sel, g->nc->wan[sel].ifname);
                    else
                        fprintf(stderr, "[%s] FAILOVER: every WAN link is down\n",
                                BRAND_PRODUCT);
                    (void)prev;
                }
                apply_routes_locked(g);
                fflush(stdout);
            }
            pthread_mutex_unlock(&g->lock);
        }

        for (int t = 0; t < g->interval_sec * 10 && g->running; t++) {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

int gwmon_init(gwmon_ctx_t *g, netconf_ctx_t *n, bool apply_net) {
    memset(g, 0, sizeof(*g));
    pthread_mutex_init(&g->lock, NULL);

    g->nc             = n;
    g->wan_count      = n ? n->wan_count : 0;
    g->apply_net      = apply_net;
    g->active_wan     = -1;
    g->interval_sec   = (n && n->monitor_interval)   ? n->monitor_interval   : GW_DEFAULT_INTERVAL;
    g->timeout_ms     = (n && n->monitor_timeout_ms) ? n->monitor_timeout_ms : GW_DEFAULT_TIMEOUT_MS;
    g->fail_threshold = (n && n->monitor_fail)       ? n->monitor_fail       : GW_DEFAULT_FAIL;
    g->ok_threshold   = (n && n->monitor_ok)         ? n->monitor_ok         : GW_DEFAULT_OK;

    for (int i = 0; i < g->wan_count; i++) {
        g->state[i].status = n->wan[i].monitor_ip[0] ? GW_UNKNOWN : GW_UNMONITORED;
        if (n->wan[i].mode == WAN_STATIC) g->state[i].gateway = n->wan[i].gateway;
    }

    /* Start on whatever the configuration prefers, so the first probe round
     * does not look like a failover. */
    g->active_wan = gwmon_select(n ? n->wan : NULL, g->state, g->wan_count);
    return 0;
}

int gwmon_start(gwmon_ctx_t *g) {
    if (!g->nc || g->wan_count <= 0) return -1;

    int monitored = 0;
    for (int i = 0; i < g->wan_count; i++)
        if (g->nc->wan[i].monitor_ip[0] && g->nc->wan[i].mode != WAN_DISABLED)
            monitored++;

    if (!monitored) {
        printf("[%s] gateway monitor idle: no WAN link has monitor_ip set\n",
               BRAND_PRODUCT);
        return 0;
    }

    g->running = true;
    if (pthread_create(&g->thread, NULL, gw_thread, g) != 0) {
        g->running = false;
        fprintf(stderr, "[%s] could not start the gateway monitor\n", BRAND_PRODUCT);
        return -1;
    }

    printf("[%s] Gateway monitor: %d link(s), every %ds, "
           "down after %d misses, up after %d replies\n",
           BRAND_PRODUCT, monitored, g->interval_sec,
           g->fail_threshold, g->ok_threshold);
    return 0;
}

void gwmon_stop(gwmon_ctx_t *g) {
    if (!g->running) return;
    g->running = false;
    pthread_join(g->thread, NULL);
}

void gwmon_shutdown(gwmon_ctx_t *g) {
    if (!g) return;
    gwmon_stop(g);
    pthread_mutex_destroy(&g->lock);
}

int gwmon_snapshot(gwmon_ctx_t *g, gw_state_t *out, int max, int *active) {
    pthread_mutex_lock(&g->lock);
    int n = g->wan_count < max ? g->wan_count : max;
    for (int i = 0; i < n; i++) out[i] = g->state[i];
    if (active) *active = g->active_wan;
    pthread_mutex_unlock(&g->lock);
    return n;
}
