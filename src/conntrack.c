/*
 * Connection state table reader. See include/conntrack.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "conntrack.h"

#define CT_PROC  "/proc/net/nf_conntrack"
#define CT_COUNT "/proc/sys/net/netfilter/nf_conntrack_count"
#define CT_MAXF  "/proc/sys/net/netfilter/nf_conntrack_max"

const char *ct_source_str(ct_source_t s) {
    switch (s) {
        case CT_SRC_PROCFS: return "procfs";
        case CT_SRC_TOOL:   return "conntrack-tools";
        default:            return "unavailable";
    }
}

static uint32_t read_u32_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long v = 0;
    if (fscanf(f, "%lu", &v) != 1) v = 0;
    fclose(f);
    return (uint32_t)v;
}

uint32_t ct_count(void) { return read_u32_file(CT_COUNT); }

/* Pulls "key=value" out of a conntrack line. The original and reply
 * directions use the same key names, so `occurrence` picks which one. */
static bool field_str(const char *line, const char *key, int occurrence,
                      char *out, size_t outlen) {
    char pat[32];
    int pl = snprintf(pat, sizeof(pat), "%s=", key);
    if (pl <= 0 || (size_t)pl >= sizeof(pat)) return false;

    const char *p = line;
    for (int seen = 0; (p = strstr(p, pat)) != NULL; ) {
        /* Must start a token, so "src=" never matches inside "xsrc=". */
        if (p != line && p[-1] != ' ' && p[-1] != '\t') { p += pl; continue; }
        if (seen++ < occurrence) { p += pl; continue; }

        p += pl;
        size_t i = 0;
        while (p[i] && p[i] != ' ' && p[i] != '\t' && p[i] != '\n' &&
               i + 1 < outlen) { out[i] = p[i]; i++; }
        out[i] = '\0';
        return i > 0;
    }
    return false;
}

static bool field_u64(const char *line, const char *key, int occurrence,
                      uint64_t *out) {
    char buf[32];
    if (!field_str(line, key, occurrence, buf, sizeof(buf))) return false;
    char *end = NULL;
    unsigned long long v = strtoull(buf, &end, 10);
    if (end == buf) return false;
    *out = (uint64_t)v;
    return true;
}

static uint32_t field_ip(const char *line, const char *key, int occurrence) {
    char buf[64];
    if (!field_str(line, key, occurrence, buf, sizeof(buf))) return 0;
    struct in_addr a;
    return (inet_pton(AF_INET, buf, &a) == 1) ? a.s_addr : 0;
}

/*
 * A /proc/net/nf_conntrack line looks like:
 *
 *   ipv4 2 tcp 6 431998 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 sport=52000 \
 *   dport=443 packets=12 bytes=1440 src=1.1.1.1 dst=10.0.0.5 sport=443 \
 *   dport=52000 packets=10 bytes=5000 [ASSURED] mark=0 use=1
 *
 * The leading fields are positional and the rest are key=value, with the
 * reply direction repeating the same keys.
 */
bool ct_parse_line(const char *line, ct_entry_t *e) {
    if (!line || !e) return false;
    memset(e, 0, sizeof(*e));

    char l3[8], proto[CT_PROTO_LEN];
    int l3num = 0, protonum = 0, ttl = 0;

    /* Some kernels omit the l3 name, so accept both layouts. */
    if (sscanf(line, "%7s %d %7s %d %d",
               l3, &l3num, proto, &protonum, &ttl) != 5) {
        if (sscanf(line, "%7s %d %d", proto, &protonum, &ttl) != 3)
            return false;
    }
    if (strcmp(l3, "ipv4") != 0 && strcmp(proto, "tcp") != 0 &&
        strcmp(proto, "udp") != 0 && strcmp(proto, "icmp") != 0) {
        /* Not an IPv4 flow we can render; skip rather than guess. */
        if (strcmp(l3, "ipv4") != 0) return false;
    }

    snprintf(e->proto, CT_PROTO_LEN, "%s", proto);
    e->ttl = ttl;

    e->src   = field_ip(line, "src", 0);
    e->dst   = field_ip(line, "dst", 0);
    if (!e->src || !e->dst) return false;

    uint64_t v;
    if (field_u64(line, "sport", 0, &v)) e->sport = (uint16_t)v;
    if (field_u64(line, "dport", 0, &v)) e->dport = (uint16_t)v;
    if (field_u64(line, "packets", 0, &v)) e->packets = v;
    if (field_u64(line, "bytes",   0, &v)) e->bytes   = v;
    if (field_u64(line, "packets", 1, &v)) e->rx_packets = v;
    if (field_u64(line, "bytes",   1, &v)) e->rx_bytes   = v;

    e->assured = strstr(line, "[ASSURED]") != NULL;

    /* TCP carries a state word between the timeout and the first src=. */
    const char *s = strstr(line, " src=");
    if (s) {
        static const char *STATES[] = {
            "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "TIME_WAIT",
            "CLOSE_WAIT", "LAST_ACK", "CLOSE", "LISTEN", "UNREPLIED", NULL };
        for (int i = 0; STATES[i]; i++) {
            const char *hit = strstr(line, STATES[i]);
            if (hit && hit < s) {
                snprintf(e->state, CT_STATE_LEN, "%s", STATES[i]);
                break;
            }
        }
    }
    if (!e->state[0])
        snprintf(e->state, CT_STATE_LEN, "%s",
                 strstr(line, "[UNREPLIED]") ? "UNREPLIED" : "-");
    return true;
}

static int read_stream(FILE *f, ct_entry_t *out, int max) {
    char line[1024];
    int n = 0;
    while (n < max && fgets(line, sizeof(line), f))
        if (ct_parse_line(line, &out[n])) n++;
    return n;
}

int ct_read(ct_entry_t *out, int max, ct_stats_t *st) {
    if (!out || !st || max <= 0) return -1;

    memset(st, 0, sizeof(*st));
    st->count = read_u32_file(CT_COUNT);
    st->max   = read_u32_file(CT_MAXF);

    FILE *f = fopen(CT_PROC, "r");
    if (f) {
        st->listed = read_stream(f, out, max);
        fclose(f);
        st->source = CT_SRC_PROCFS;
        return st->listed;
    }
    int proc_errno = errno;

    /* conntrack-tools prints the same key=value shape on stdout. */
    FILE *p = popen("conntrack -L 2>/dev/null", "r");
    if (p) {
        st->listed = read_stream(p, out, max);
        int rc = pclose(p);
        if (rc == 0 || st->listed > 0) {
            st->source = CT_SRC_TOOL;
            return st->listed;
        }
    }

    st->source = CT_SRC_NONE;
    snprintf(st->source_detail, sizeof(st->source_detail),
             "%s: %s. conntrack-tools is not installed either. The kernel "
             "is tracking %u connection(s), so the capacity figures below "
             "are real; listing individual flows needs either "
             "CONFIG_NF_CONNTRACK_PROCFS or the conntrack command.",
             CT_PROC, strerror(proc_errno), st->count);
    return 0;
}
