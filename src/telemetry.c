/*
 * Remote syslog and NetFlow v5 export. See include/telemetry.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "telemetry.h"
#include "egress.h"
#include "inspect.h"
#include "netutil.h"
#include "brand.h"

/* ── wire formats ───────────────────────────────────────────────────── */

int syslog_format(char *out, size_t outlen, int facility, int severity,
                  time_t when, const char *hostname, const char *app,
                  const char *msgid, const char *msg) {
    if (!out || outlen < 64) return -1;
    if (facility < 0 || facility > 23) facility = 16;
    if (severity < 0 || severity > 7)  severity = 6;

    if (!when) when = time(NULL);
    struct tm tmv;
    gmtime_r(&when, &tmv);
    char stamp[40];
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tmv);

    /* PRI = facility * 8 + severity, then VERSION 1. The three '-' are
     * PROCID, STRUCTURED-DATA and (when absent) MSGID. */
    int n = snprintf(out, outlen, "<%d>1 %s %s %s - %s - %s",
                     facility * 8 + severity, stamp,
                     (hostname && *hostname) ? hostname : "-",
                     (app && *app) ? app : BRAND_DAEMON,
                     (msgid && *msgid) ? msgid : "-",
                     msg ? msg : "");
    if (n < 0 || (size_t)n >= outlen) return -1;
    return n;
}

/* NetFlow v5 is big-endian throughout; these helpers keep that explicit. */
static void put16(uint8_t *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }

int netflow_v5_build(uint8_t *out, size_t outlen, const ct_entry_t *entries,
                     int n, uint32_t uptime_ms, time_t now, uint32_t sequence) {
    if (!out || !entries || n <= 0) return -1;
    if (n > NETFLOW_MAX_RECORDS) n = NETFLOW_MAX_RECORDS;

    size_t need = NETFLOW_V5_HDR_LEN + (size_t)n * NETFLOW_V5_REC_LEN;
    if (outlen < need) return -1;
    memset(out, 0, need);

    put16(out + 0,  5);                      /* version            */
    put16(out + 2,  (uint16_t)n);            /* record count       */
    put32(out + 4,  uptime_ms);              /* sysUptime          */
    put32(out + 8,  (uint32_t)now);          /* unix_secs          */
    put32(out + 12, 0);                      /* unix_nsecs         */
    put32(out + 16, sequence);               /* flow_sequence      */
    out[20] = 0;                             /* engine_type        */
    out[21] = 0;                             /* engine_id          */
    put16(out + 22, 0);                      /* sampling_interval  */

    for (int i = 0; i < n; i++) {
        uint8_t *r = out + NETFLOW_V5_HDR_LEN + (size_t)i * NETFLOW_V5_REC_LEN;
        const ct_entry_t *e = &entries[i];

        memcpy(r + 0, &e->src, 4);           /* srcaddr, already network order */
        memcpy(r + 4, &e->dst, 4);           /* dstaddr                        */
        put32(r + 8,  0);                    /* nexthop  - not tracked         */
        put16(r + 12, 0);                    /* input    snmp index            */
        put16(r + 14, 0);                    /* output                         */

        /* v5 counters are 32-bit; a long-lived flow can exceed that, so
         * saturate rather than wrap into a nonsense value. */
        uint64_t pk = e->packets, by = e->bytes;
        put32(r + 16, pk > 0xffffffffULL ? 0xffffffffU : (uint32_t)pk);
        put32(r + 20, by > 0xffffffffULL ? 0xffffffffU : (uint32_t)by);

        /* first/last are sysUptime-relative. The connection table gives a
         * remaining TTL, not a start time, so both are stamped now: the
         * durations are honestly unknown rather than invented. */
        put32(r + 24, uptime_ms);
        put32(r + 28, uptime_ms);

        put16(r + 32, e->sport);
        put16(r + 34, e->dport);
        r[36] = 0;                           /* pad1      */
        r[37] = 0;                           /* tcp_flags */

        uint8_t proto = 0;
        if      (!strcmp(e->proto, "tcp"))  proto = 6;
        else if (!strcmp(e->proto, "udp"))  proto = 17;
        else if (!strcmp(e->proto, "icmp")) proto = 1;
        r[38] = proto;
        r[39] = 0;                           /* tos */
        put16(r + 40, 0);                    /* src_as   */
        put16(r + 42, 0);                    /* dst_as   */
        r[44] = 32;                          /* src_mask */
        r[45] = 32;                          /* dst_mask */
        put16(r + 46, 0);                    /* pad2     */
    }
    return (int)need;
}

/* ── sockets ────────────────────────────────────────────────────────── */

bool telemetry_has_syslog(const telemetry_ctx_t *t) {
    return t && t->cfg.syslog_host[0] != '\0';
}
bool telemetry_has_netflow(const telemetry_ctx_t *t) {
    return t && t->cfg.netflow_host[0] != '\0';
}

/*
 * Gating connect_collector() alone would not be enough. The collector
 * socket is opened once at init and then written to for the life of the
 * daemon, so an appliance that was connected at boot and is isolated an
 * hour later would keep shipping down an fd that predates the decision.
 * Every send asks as well.
 */
static bool telem_may_send(void) {
    return egress_permitted(EGRESS_TELEMETRY, NULL, 0);
}

static int connect_collector(const char *host, uint16_t port, bool tcp) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM;

    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    /* A dead collector must not stall the exporter. */
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

int telemetry_init(telemetry_ctx_t *t, const telemetry_cfg_t *cfg) {
    memset(t, 0, sizeof(*t));
    pthread_mutex_init(&t->lock, NULL);
    t->syslog_fd  = -1;
    t->netflow_fd = -1;
    t->boot       = time(NULL);
    if (cfg) t->cfg = *cfg;

    if (!t->cfg.syslog_port)      t->cfg.syslog_port = 514;
    if (!t->cfg.netflow_port)     t->cfg.netflow_port = 2055;
    if (!t->cfg.netflow_interval) t->cfg.netflow_interval = 60;
    if (!t->cfg.syslog_facility)  t->cfg.syslog_facility = 16;   /* local0 */
    if (!t->cfg.syslog_min_severity) t->cfg.syslog_min_severity = SYSLOG_INFO;

    if (telemetry_has_syslog(t) && telem_may_send()) {
        t->syslog_fd = connect_collector(t->cfg.syslog_host, t->cfg.syslog_port,
                                         t->cfg.syslog_tcp);
        if (t->syslog_fd < 0)
            fprintf(stderr, "[%s] syslog collector %s:%u unreachable (%s); "
                    "messages will be dropped\n", BRAND_PRODUCT,
                    t->cfg.syslog_host, t->cfg.syslog_port, strerror(errno));
    }
    if (telemetry_has_netflow(t) && telem_may_send()) {
        t->netflow_fd = connect_collector(t->cfg.netflow_host,
                                          t->cfg.netflow_port, false);
        if (t->netflow_fd < 0)
            fprintf(stderr, "[%s] NetFlow collector %s:%u unreachable (%s)\n",
                    BRAND_PRODUCT, t->cfg.netflow_host, t->cfg.netflow_port,
                    strerror(errno));
    }
    return 0;
}

static uint32_t uptime_ms(const telemetry_ctx_t *t) {
    return (uint32_t)((time(NULL) - t->boot) * 1000);
}

void telemetry_log(telemetry_ctx_t *t, syslog_severity_t sev,
                   const char *msgid, const char *fmt, ...) {
    if (!telemetry_has_syslog(t)) return;
    if ((int)sev > t->cfg.syslog_min_severity) return;

    char msg[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    char host[64];
    if (gethostname(host, sizeof(host)) != 0) snprintf(host, sizeof(host), "-");
    host[sizeof(host) - 1] = '\0';

    char frame[1024];
    int n = syslog_format(frame, sizeof(frame), t->cfg.syslog_facility,
                          (int)sev, 0, host, BRAND_DAEMON, msgid, msg);
    if (n < 0) return;

    /*
     * Asked before t->lock is taken, not under it. The bound predicate
     * takes the air gap's mutex, and nesting the two here would make
     * "telemetry lock before air-gap lock" a rule every future caller of
     * either had to know. The refusal still counts as a drop, because from
     * the operator's side the message did not arrive.
     */
    bool may = telem_may_send();

    pthread_mutex_lock(&t->lock);
    if (t->syslog_fd < 0 || !may) {
        t->syslog_dropped++;
        pthread_mutex_unlock(&t->lock);
        return;
    }

    ssize_t w;
    if (t->cfg.syslog_tcp) {
        /* RFC 6587 octet counting: the frame is preceded by its length. */
        char tcpframe[1100];
        int tn = snprintf(tcpframe, sizeof(tcpframe), "%d %s", n, frame);
        w = (tn > 0) ? send(t->syslog_fd, tcpframe, (size_t)tn, MSG_NOSIGNAL) : -1;
    } else {
        w = send(t->syslog_fd, frame, (size_t)n, MSG_NOSIGNAL);
    }

    if (w < 0) {
        t->syslog_dropped++;
        /* A TCP collector that went away needs a new connection; dropping the
         * socket here makes the next tick reconnect. */
        if (t->cfg.syslog_tcp) { close(t->syslog_fd); t->syslog_fd = -1; }
    } else {
        t->syslog_sent++;
    }
    pthread_mutex_unlock(&t->lock);
}

int telemetry_export_flows(telemetry_ctx_t *t) {
    if (!telemetry_has_netflow(t) || t->netflow_fd < 0) return 0;
    if (!telem_may_send()) return 0;

    ct_entry_t *entries = calloc(CT_MAX_ENTRIES, sizeof(*entries));
    if (!entries) return 0;

    ct_stats_t st;
    int n = ct_read(entries, CT_MAX_ENTRIES, &st);
    if (n <= 0) { free(entries); return 0; }

    uint8_t pkt[NETFLOW_V5_HDR_LEN + NETFLOW_MAX_RECORDS * NETFLOW_V5_REC_LEN];
    int sent = 0;

    for (int off = 0; off < n; off += NETFLOW_MAX_RECORDS) {
        int batch = n - off;
        if (batch > NETFLOW_MAX_RECORDS) batch = NETFLOW_MAX_RECORDS;

        pthread_mutex_lock(&t->lock);
        uint32_t seq = t->flow_sequence;
        t->flow_sequence += (uint32_t)batch;
        pthread_mutex_unlock(&t->lock);

        int len = netflow_v5_build(pkt, sizeof(pkt), entries + off, batch,
                                   uptime_ms(t), time(NULL), seq);
        if (len < 0) break;

        if (send(t->netflow_fd, pkt, (size_t)len, MSG_NOSIGNAL) == len) {
            pthread_mutex_lock(&t->lock);
            t->flows_sent += (unsigned long)batch;
            t->netflow_packets++;
            pthread_mutex_unlock(&t->lock);
            sent += batch;
        }
    }

    free(entries);
    return sent;
}

/* Forwards block events that have appeared since the last pass. */
static void forward_block_events(telemetry_ctx_t *t) {
    if (!telemetry_has_syslog(t)) return;

    pthread_mutex_lock(&g_blockpage.lock);
    int count = g_blockpage.event_count;
    pthread_mutex_unlock(&g_blockpage.lock);

    if (t->event_cursor > count) t->event_cursor = 0;   /* ring was reset */

    char sbuf[INET_ADDRSTRLEN];
    while (t->event_cursor < count) {
        block_event_t e;
        pthread_mutex_lock(&g_blockpage.lock);
        if (t->event_cursor >= g_blockpage.event_count) {
            pthread_mutex_unlock(&g_blockpage.lock);
            break;
        }
        e = g_blockpage.events[t->event_cursor];
        pthread_mutex_unlock(&g_blockpage.lock);
        t->event_cursor++;

        telemetry_log(t, e.severity >= 4 ? SYSLOG_ALERT : SYSLOG_WARNING,
                      "BLOCK",
                      "rid=%s client=%s vlan=%u(%s) zone=%s host=\"%s\" "
                      "policy=%s reason=\"%s\"",
                      e.request_id, fx_ip_str(e.client_ip, sbuf, sizeof(sbuf)),
                      e.vlan_id, e.vlan_name, e.zone, e.host,
                      e.policy_id, e.detail);
    }
}

static void *telem_thread(void *arg) {
    telemetry_ctx_t *t = arg;
    time_t next_flow = time(NULL) + t->cfg.netflow_interval;

    while (t->running) {
        forward_block_events(t);

        if (telemetry_has_netflow(t) && time(NULL) >= next_flow) {
            telemetry_export_flows(t);
            next_flow = time(NULL) + t->cfg.netflow_interval;
        }

        /* Reconnect a TCP syslog collector that dropped. */
        pthread_mutex_lock(&t->lock);
        bool reconnect = telemetry_has_syslog(t) && t->cfg.syslog_tcp &&
                         t->syslog_fd < 0;
        pthread_mutex_unlock(&t->lock);
        if (reconnect) {
            int fd = connect_collector(t->cfg.syslog_host, t->cfg.syslog_port, true);
            pthread_mutex_lock(&t->lock);
            t->syslog_fd = fd;
            pthread_mutex_unlock(&t->lock);
        }

        for (int i = 0; i < 20 && t->running; i++) {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

int telemetry_start(telemetry_ctx_t *t) {
    if (!telemetry_has_syslog(t) && !telemetry_has_netflow(t)) return 0;

    t->running = true;
    if (pthread_create(&t->thread, NULL, telem_thread, t) != 0) {
        t->running = false;
        fprintf(stderr, "[%s] could not start the telemetry exporter\n",
                BRAND_PRODUCT);
        return -1;
    }

    if (telemetry_has_syslog(t))
        printf("[%s] Syslog -> %s:%u/%s, facility local%d\n", BRAND_PRODUCT,
               t->cfg.syslog_host, t->cfg.syslog_port,
               t->cfg.syslog_tcp ? "tcp" : "udp",
               t->cfg.syslog_facility - 16);
    if (telemetry_has_netflow(t))
        printf("[%s] NetFlow v5 -> %s:%u every %ds\n", BRAND_PRODUCT,
               t->cfg.netflow_host, t->cfg.netflow_port,
               t->cfg.netflow_interval);
    return 0;
}

void telemetry_stop(telemetry_ctx_t *t) {
    if (!t->running) return;
    t->running = false;
    pthread_join(t->thread, NULL);
}

void telemetry_shutdown(telemetry_ctx_t *t) {
    if (!t) return;
    telemetry_stop(t);
    if (t->syslog_fd  >= 0) close(t->syslog_fd);
    if (t->netflow_fd >= 0) close(t->netflow_fd);
    t->syslog_fd = t->netflow_fd = -1;
    pthread_mutex_destroy(&t->lock);
}
