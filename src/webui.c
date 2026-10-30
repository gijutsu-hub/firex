#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <errno.h>
#include <sys/timex.h>

#include "webui.h"
#include "inspect.h"
#include "reload.h"
#include "config_write.h"
#include "egress.h"
#include "audit.h"
#include "policy.h"
#include "gwmon.h"
#include "vpn.h"
#include "conntrack.h"
#include "histstats.h"
#include "capture.h"
#include "telemetry.h"
#include "shaper.h"
#include "portal.h"
#include "ha.h"
#include "ids.h"
#include "feeds.h"
#include "response.h"
#include "malware.h"
#include "airgap.h"
#include "netif.h"
#include "netutil.h"
#include "brand.h"

/* Only these three names are servable; there is no path mapping at all, so a
 * traversal attempt cannot reach the filesystem. */
extern const char WEBUI_INDEX_HTML[];
extern const char WEBUI_VLAN_JS[];
extern const char WEBUI_STYLE_CSS[];

auth_ctx_t g_auth;
cfgstore_t g_cfgstore;

static char g_config_path[CFG_PATH_LEN];
static char g_capture_dir[CFG_PATH_LEN] = "/run/firex";
static bool g_apply_net;
static bool g_ready;

/* ═══════════════════════ small helpers ═══════════════════════ */

static void json_escape(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)(in ? in : ""); *p; p++) {
        char esc[8];
        const char *rep = esc;
        size_t rl;
        switch (*p) {
            case '"':  rep = "\\\""; rl = 2; break;
            case '\\': rep = "\\\\"; rl = 2; break;
            case '\n': rep = "\\n";  rl = 2; break;
            case '\r': rep = "\\r";  rl = 2; break;
            case '\t': rep = "\\t";  rl = 2; break;
            default:
                if (*p < 0x20) { snprintf(esc, sizeof(esc), "\\u%04x", *p); rl = 6; }
                else           { esc[0] = (char)*p; esc[1] = 0; rl = 1; }
        }
        if (o + rl >= outlen - 1) break;
        memcpy(out + o, rep, rl);
        o += rl;
    }
    out[o] = '\0';
}

static void send_json(int fd, const char *status, const char *body) {
    blockpage_send(fd, status, "application/json", body, strlen(body));
}

/* Error bodies are built from fixed strings and already-escaped detail. */
static void send_err(int fd, const char *status, const char *msg) {
    char esc[CFG_ERR_LEN * 2], buf[CFG_ERR_LEN * 2 + 32];
    json_escape(msg, esc, sizeof(esc));
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", esc);
    send_json(fd, status, buf);
}

/*
 * Minimal reader for a flat JSON object. It does not descend into nested
 * objects or arrays, which is all these endpoints accept -- anything deeper
 * simply reads as absent rather than being misparsed.
 */
static const char *json_find(const char *b, size_t len, const char *key) {
    char pat[64];
    int pl = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (pl <= 0 || (size_t)pl >= sizeof(pat)) return NULL;

    for (size_t i = 0; i + (size_t)pl <= len; i++) {
        if (memcmp(b + i, pat, (size_t)pl) != 0) continue;
        size_t j = i + (size_t)pl;
        while (j < len && (b[j]==' '||b[j]=='\t'||b[j]=='\n'||b[j]=='\r')) j++;
        if (j >= len || b[j] != ':') continue;
        j++;
        while (j < len && (b[j]==' '||b[j]=='\t'||b[j]=='\n'||b[j]=='\r')) j++;
        return (j < len) ? b + j : NULL;
    }
    return NULL;
}

static bool json_str(const char *b, size_t len, const char *key,
                     char *out, size_t outlen) {
    const char *p = json_find(b, len, key);
    if (!p || *p != '"') return false;
    p++;

    const char *end = b + len;
    size_t o = 0;
    while (p < end && *p != '"') {
        char c = *p;
        if (c == '\\' && p + 1 < end) {
            p++;
            switch (*p) {
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'u': {
                    /* Only the ASCII range is represented; anything above it
                     * becomes '?' rather than mangled bytes. */
                    if (p + 4 >= end) return false;
                    char hex[5] = { p[1], p[2], p[3], p[4], 0 };
                    long v = strtol(hex, NULL, 16);
                    c = (v >= 0x20 && v < 0x7f) ? (char)v : '?';
                    p += 4;
                    break;
                }
                default: c = *p; break;
            }
        }
        if (o + 1 >= outlen) return false;      /* too long: reject, not truncate */
        out[o++] = c;
        p++;
    }
    if (p >= end) return false;                  /* unterminated string */
    out[o] = '\0';
    return true;
}

static bool json_int(const char *b, size_t len, const char *key, long *out) {
    const char *p = json_find(b, len, key);
    if (!p) return false;
    char buf[32];
    size_t o = 0;
    const char *end = b + len;
    if (p < end && (*p == '-' || *p == '+')) buf[o++] = *p++;
    while (p < end && *p >= '0' && *p <= '9' && o + 1 < sizeof(buf)) buf[o++] = *p++;
    if (!o || (o == 1 && !(buf[0] >= '0' && buf[0] <= '9'))) return false;
    buf[o] = '\0';
    *out = strtol(buf, NULL, 10);
    return true;
}

static bool json_bool(const char *b, size_t len, const char *key, bool *out) {
    const char *p = json_find(b, len, key);
    if (!p) return false;
    size_t left = (size_t)(b + len - p);
    if (left >= 4 && !memcmp(p, "true", 4))  { *out = true;  return true; }
    if (left >= 5 && !memcmp(p, "false", 5)) { *out = false; return true; }
    return false;
}

/* Pull one cookie out of the raw request headers. */
static bool cookie_get(const char *headers, const char *name,
                       char *out, size_t outlen) {
    const char *line = strcasestr(headers, "\nCookie:");
    if (!line) return false;
    line += 8;
    const char *eol = strpbrk(line, "\r\n");
    if (!eol) eol = line + strlen(line);

    size_t nlen = strlen(name);
    for (const char *p = line; p < eol; p++) {
        if (p != line && *(p-1) != ' ' && *(p-1) != ';') continue;
        if ((size_t)(eol - p) < nlen + 1) break;
        if (memcmp(p, name, nlen) || p[nlen] != '=') continue;

        const char *v = p + nlen + 1;
        size_t o = 0;
        while (v < eol && *v != ';' && *v != ' ' && o + 1 < outlen) out[o++] = *v++;
        out[o] = '\0';
        return o > 0;
    }
    return false;
}

static bool header_get(const char *headers, const char *name,
                       char *out, size_t outlen) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\n%s:", name);
    const char *line = strcasestr(headers, pat);
    if (!line) return false;
    line += strlen(pat);
    while (*line == ' ' || *line == '\t') line++;
    const char *eol = strpbrk(line, "\r\n");
    if (!eol) eol = line + strlen(line);

    size_t o = 0;
    while (line < eol && o + 1 < outlen) out[o++] = *line++;
    out[o] = '\0';
    return o > 0;
}

/* ═══════════════════════ auth gate ═══════════════════════ */

/*
 * Resolves the caller's session. Returns false and has already answered the
 * request when the caller is not allowed through. `need_admin` additionally
 * demands the admin role and a matching CSRF token -- the token is only ever
 * required for state-changing calls, so a plain GET stays a plain GET.
 */

/* ═══════════════════ administrative audit ═══════════════════
 *
 * Every write endpoint lands here. The dispatcher records the request
 * itself; a handler that knows something the path does not -- which mode,
 * which account, which interface -- records that instead and sets
 * t_audited so the two do not both appear.
 */
audit_ctx_t g_audit;

/*
 * Runtime changes that are not yet in the configuration file.
 *
 * The console follows a running/saved split: a mode change takes effect at
 * once, and Save writes it out. That is the right model -- it is how an
 * operator tries something and backs out of it -- but the previous version
 * never said which state you were in. Isolating an appliance, rebooting
 * it and finding it connected again is the kind of surprise that teaches
 * people not to trust the control.
 *
 * Counted rather than a bool so the console can say how many, and so two
 * changes followed by one save cannot leave it reading "clean".
 */
static unsigned g_unsaved;

static void mark_unsaved(void) { __atomic_add_fetch(&g_unsaved, 1, __ATOMIC_RELAXED); }
static void mark_saved(void)   { __atomic_store_n(&g_unsaved, 0, __ATOMIC_RELAXED); }
static unsigned unsaved(void)  { return __atomic_load_n(&g_unsaved, __ATOMIC_RELAXED); }

/*
 * The air-gap mode the appliance would come back in. Read from the file on
 * disk, not from g_netconf -- g_netconf IS the running state, so comparing
 * against it would always say "no change" and the hint would be a lie
 * exactly when it matters.
 */
static ag_mode_t g_netconf_saved_airgap_mode(void) {
    FILE *f = fopen(g_config_path, "r");
    if (!f) return AG_CONNECTED;

    char line[256];
    bool in_airgap = false;
    ag_mode_t m = AG_CONNECTED;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '[') { in_airgap = !strncmp(p, "[airgap]", 8); continue; }
        if (!in_airgap) continue;
        if (strncmp(p, "mode", 4)) continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        eq++;
        while (*eq == ' ' || *eq == '\t') eq++;
        char *nl = strpbrk(eq, " \t\r\n#");
        if (nl) *nl = 0;
        airgap_mode_from_name(eq, &m);
        break;
    }
    fclose(f);
    return m;
}

static __thread bool     t_audited;
static __thread uint32_t t_peer;
static __thread char     t_actor[AUDIT_ACTOR_LEN];

static void audited(audit_result_t r, const char *action, const char *target,
                    const char *fmt, ...) __attribute__((format(printf, 4, 5)));

static void audited(audit_result_t r, const char *action, const char *target,
                    const char *fmt, ...) {
    char detail[AUDIT_DETAIL_LEN] = "";
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(detail, sizeof(detail), fmt, ap);
        va_end(ap);
    }
    audit_record(&g_audit, t_actor, t_peer, r, action, target, "%s", detail);
    t_audited = true;
}

static bool gate(int fd, const char *headers, const char *method,
                 bool need_admin, fx_session_t *out) {
    if (!g_ready) {
        send_err(fd, "503 Service Unavailable",
                 "console not initialised; no user database");
        return false;
    }

    char token[AUTH_TOKEN_LEN];
    if (!cookie_get(headers, "firex_session", token, sizeof(token)) ||
        !auth_session(&g_auth, token, out)) {
        send_json(fd, "401 Unauthorized",
                  "{\"error\":\"authentication required\",\"login\":true}");
        return false;
    }

    if (!need_admin) return true;

    if (out->role != ROLE_ADMIN) {
        /*
         * A read-only account reaching for a write is worth a record
         * whether it was a mis-click or the first probe of a session that
         * matters later. The actor is known here, which is the whole
         * reason it is recorded here and not in the dispatcher.
         */
        snprintf(t_actor, sizeof(t_actor), "%s", out->user);
        audited(AUDIT_DENIED, "authz.deny", method,
                "%s is read-only and attempted a write", out->user);
        send_err(fd, "403 Forbidden", "this account is read-only");
        return false;
    }

    /* Double-submit CSRF: the cookie alone must never be enough to act. */
    char csrf[AUTH_CSRF_LEN];
    if (!header_get(headers, "X-FireX-CSRF", csrf, sizeof(csrf)) ||
        !auth_csrf_ok(out, csrf)) {
        snprintf(t_actor, sizeof(t_actor), "%s", out->user);
        audited(AUDIT_DENIED, "csrf.reject", method,
                "a write arrived with a missing or stale CSRF token");
        send_err(fd, "403 Forbidden", "missing or invalid CSRF token");
        return false;
    }

    (void)method;
    return true;
}

/* ═══════════════════════ read endpoints ═══════════════════════ */

static const char *action_json(ivr_action_t a) {
    switch (a) {
        case IVR_ALLOW:     return "ALLOW";
        case IVR_LOG_ALLOW: return "LOG_ALLOW";
        case IVR_LOG_DENY:  return "LOG_DENY";
        default:            return "DENY";
    }
}

static ivr_action_t action_from(const char *s) {
    if (!strcasecmp(s, "ALLOW"))     return IVR_ALLOW;
    if (!strcasecmp(s, "LOG_ALLOW")) return IVR_LOG_ALLOW;
    if (!strcasecmp(s, "LOG_DENY"))  return IVR_LOG_DENY;
    return IVR_DENY;
}

static zone_t zone_from(const char *s) {
    for (int z = 0; z < ZONE_MAX; z++)
        if (!strcasecmp(s, zone_name(z))) return (zone_t)z;
    return ZONE_MAX;
}

static void api_vlans(int fd, const fx_session_t *s) {
    size_t cap = 96 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t n = 0;
    char a[INET_ADDRSTRLEN], g[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN], de[INET_ADDRSTRLEN];
    char esc[256];

    /* The temporary is underscored: an argument named `w` would otherwise be
     * captured by this declaration rather than referring to the caller's. */
    #define APP(...) do { \
        int _apw = snprintf(b + n, cap - n, __VA_ARGS__); \
        if (_apw < 0 || (size_t)_apw >= cap - n) { goto done; } \
        n += (size_t)_apw; } while (0)

    pthread_mutex_lock(&g_vlan.lock);

    APP("{\"vlans\":[");
    for (int i = 0; i < g_vlan.vlan_count; i++) {
        vlan_config_t *v = &g_vlan.vlans[i];
        json_escape(v->name, esc, sizeof(esc));
        APP("%s{\"vlan_id\":%u,\"name\":\"%s\",\"zone\":\"%s\","
            "\"subnet\":\"%s\",\"cidr\":%d,\"gateway\":\"%s\","
            "\"dhcp\":%s,\"dhcp_start\":\"%s\",\"dhcp_end\":\"%s\","
            "\"internet\":%s,\"inter_vlan\":%s,\"isolation\":%s,"
            "\"dpi\":%s,\"ips\":%s,\"malware_scan\":%s,\"log_all\":%s,"
            "\"captive_portal\":%s,\"show_block_page\":%s,"
            "\"lease_time\":%d,\"priority\":%u,\"max_clients\":%d,"
            "\"clients\":%d,\"rx_packets\":%lu,\"blocked\":%lu}",
            i ? "," : "", v->vlan_id, esc, zone_name(v->zone),
            fx_ip_str(v->subnet, a, sizeof(a)), fx_netmask_to_cidr(v->netmask),
            fx_ip_str(v->gateway, g, sizeof(g)),
            v->dhcp_enabled ? "true" : "false",
            fx_ip_str(v->dhcp_start, ds, sizeof(ds)),
            fx_ip_str(v->dhcp_end, de, sizeof(de)),
            v->internet_access ? "true" : "false",
            v->inter_vlan_routing ? "true" : "false",
            v->client_isolation ? "true" : "false",
            v->dpi_enabled ? "true" : "false",
            v->ips_enabled ? "true" : "false",
            v->malware_scan ? "true" : "false",
            v->log_all ? "true" : "false",
            v->captive_portal ? "true" : "false",
            v->show_block_page ? "true" : "false",
            v->lease_time, v->priority, v->max_clients,
            v->active_clients, v->rx_packets, v->blocked_packets);
    }

    APP("],\"ports\":[");
    for (int i = 0; i < g_vlan.port_count; i++) {
        port_config_t *p = &g_vlan.ports[i];
        json_escape(p->label, esc, sizeof(esc));
        APP("%s{\"ifname\":\"%s\",\"label\":\"%s\",\"mode\":\"%s\","
            "\"zone\":\"%s\",\"pvid\":%u,\"link_up\":%s,\"speed\":%d,"
            "\"rx_packets\":%lu,\"allowed_vlans\":[",
            i ? "," : "", p->ifname, esc, port_mode_name(p->mode),
            zone_name(p->zone), p->pvid, p->link_up ? "true" : "false",
            p->speed_mbps, p->rx_packets);
        for (int j = 0; j < p->allowed_count; j++)
            APP("%s%u", j ? "," : "", p->allowed_vlans[j]);
        APP("]}");
    }

    APP("],\"zones\":[");
    for (int z = 0; z < ZONE_MAX; z++)
        APP("%s\"%s\"", z ? "," : "", zone_name(z));

    APP("],\"matrix\":[");
    for (int f = 0; f < ZONE_MAX; f++) {
        APP("%s[", f ? "," : "");
        for (int t = 0; t < ZONE_MAX; t++)
            APP("%s\"%s\"", t ? "," : "", action_json(g_vlan.zone_matrix[f][t]));
        APP("]");
    }

    APP("],\"acl_count\":%d,\"readonly\":%s,\"role\":\"%s\","
        "\"stats\":{\"allowed\":%lu,\"denied\":%lu,\"violations\":%lu,"
        "\"tagged_rx\":%lu,\"untagged_rx\":%lu}}",
        g_vlan.ivr_count,
        s->role == ROLE_ADMIN ? "false" : "true", auth_role_name(s->role),
        g_vlan.inter_vlan_allowed, g_vlan.inter_vlan_denied,
        g_vlan.vlan_violations, g_vlan.tagged_rx, g_vlan.untagged_rx);

done:
    pthread_mutex_unlock(&g_vlan.lock);
    #undef APP
    blockpage_send(fd, "200 OK", "application/json", b, n);
    free(b);
}

static void api_events(int fd) {
    size_t cap = 256 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t n = 0;
    char a[INET_ADDRSTRLEN], esc[600];

    /* The temporary is underscored: an argument named `w` would otherwise be
     * captured by this declaration rather than referring to the caller's. */
    #define APP(...) do { \
        int _apw = snprintf(b + n, cap - n, __VA_ARGS__); \
        if (_apw < 0 || (size_t)_apw >= cap - n) { goto done; } \
        n += (size_t)_apw; } while (0)

    pthread_mutex_lock(&g_blockpage.lock);
    APP("{\"pages_served\":%lu,\"override_requests\":%lu,\"events\":[",
        g_blockpage.pages_served, g_blockpage.override_requests);

    for (int i = 0; i < g_blockpage.event_count; i++) {
        block_event_t *e = &g_blockpage.events[i];
        APP("%s{\"request_id\":\"%s\",\"time\":%ld,\"client_ip\":\"%s\","
            "\"vlan_id\":%u,", i ? "," : "", e->request_id, (long)e->timestamp,
            fx_ip_str(e->client_ip, a, sizeof(a)), e->vlan_id);
        json_escape(e->vlan_name, esc, sizeof(esc)); APP("\"vlan_name\":\"%s\",", esc);
        json_escape(e->zone, esc, sizeof(esc));      APP("\"zone\":\"%s\",", esc);
        json_escape(e->host, esc, sizeof(esc));      APP("\"host\":\"%s\",", esc);
        json_escape(e->policy_id, esc, sizeof(esc)); APP("\"policy_id\":\"%s\",", esc);
        json_escape(e->detail, esc, sizeof(esc));    APP("\"detail\":\"%s\",", esc);
        APP("\"reason\":\"%s\",\"severity\":%d}",
            blockpage_reason_title(e->reason), e->severity);
    }
    APP("]}");

done:
    pthread_mutex_unlock(&g_blockpage.lock);
    #undef APP
    blockpage_send(fd, "200 OK", "application/json", b, n);
    free(b);
}

/* ---- GET /api/policy : aliases, schedules and static routes ---- */
static void api_policy(int fd) {
    size_t cap = 64 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t n = 0;
    char esc[POLICY_DESC_LEN * 2], entries[2048], days[64], hh1[8], hh2[8];
    time_t now = time(NULL);

    /* The temporary is underscored: an argument named `w` would otherwise be
     * captured by this declaration rather than referring to the caller's. */
    #define APP(...) do { \
        int _apw = snprintf(b + n, cap - n, __VA_ARGS__); \
        if (_apw < 0 || (size_t)_apw >= cap - n) { goto done; } \
        n += (size_t)_apw; } while (0)

    pthread_mutex_lock(&g_policy.lock);

    APP("{\"aliases\":[");
    for (int i = 0; i < g_policy.alias_count; i++) {
        alias_t *a = &g_policy.aliases[i];
        json_escape(a->description, esc, sizeof(esc));
        policy_entries_str(a, entries, sizeof(entries));
        char eesc[2048];
        json_escape(entries, eesc, sizeof(eesc));
        APP("%s{\"name\":\"%s\",\"kind\":\"%s\",\"description\":\"%s\","
            "\"entries\":\"%s\",\"count\":%d,\"hits\":%lu}",
            i ? "," : "", a->name, policy_alias_kind_str(a->kind), esc,
            eesc, a->count, a->hits);
    }

    APP("],\"schedules\":[");
    for (int i = 0; i < g_policy.schedule_count; i++) {
        schedule_t *sc = &g_policy.schedules[i];
        json_escape(sc->description, esc, sizeof(esc));
        APP("%s{\"name\":\"%s\",\"description\":\"%s\",\"days\":\"%s\","
            "\"start\":\"%s\",\"end\":\"%s\",\"active\":%s}",
            i ? "," : "", sc->name, esc,
            policy_days_str(sc->days, days, sizeof(days)),
            policy_hhmm_str(sc->start_min, hh1, sizeof(hh1)),
            policy_hhmm_str(sc->end_min, hh2, sizeof(hh2)),
            policy_window_active(sc, now) ? "true" : "false");
    }
    pthread_mutex_unlock(&g_policy.lock);

    APP("],\"routes\":[");
    pthread_mutex_lock(&g_netconf.lock);
    char d[INET_ADDRSTRLEN], g[INET_ADDRSTRLEN];
    for (int i = 0; i < g_netconf.route_count; i++) {
        static_route_t *r = &g_netconf.routes[i];
        json_escape(r->description, esc, sizeof(esc));
        APP("%s{\"dest\":\"%s\",\"cidr\":%d,\"gateway\":\"%s\","
            "\"ifname\":\"%s\",\"metric\":%d,\"description\":\"%s\"}",
            i ? "," : "", fx_ip_str(r->dest, d, sizeof(d)),
            fx_netmask_to_cidr(r->mask), fx_ip_str(r->gateway, g, sizeof(g)),
            r->ifname, r->metric, esc);
    }
    pthread_mutex_unlock(&g_netconf.lock);
    APP("],\"schedule_skipped\":%lu}", g_vlan.schedule_skipped);

    blockpage_send(fd, "200 OK", "application/json", b, n);
    free(b);
    return;

done:
    #undef APP
    pthread_mutex_unlock(&g_policy.lock);
    send_err(fd, "500 Internal Server Error", "policy response too large");
    free(b);
}

/* ---- GET /api/wan : links plus live gateway-monitor state ---- */
static void api_wan(int fd) {
    gw_state_t st[2];
    int active = -1;
    int gn = gwmon_snapshot(&g_gwmon, st, 2, &active);

    size_t cap = 8 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char ip[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];

    o += (size_t)snprintf(b + o, cap - o,
             "{\"active\":%d,\"interval\":%d,\"fail_threshold\":%d,"
             "\"ok_threshold\":%d,\"links\":[",
             active, g_gwmon.interval_sec, g_gwmon.fail_threshold,
             g_gwmon.ok_threshold);

    pthread_mutex_lock(&g_netconf.lock);
    for (int i = 0; i < g_netconf.wan_count && o < cap - 512; i++) {
        wan_config_t *w = &g_netconf.wan[i];
        gw_state_t *s = (i < gn) ? &st[i] : NULL;

        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"index\":%d,\"ifname\":\"%s\",\"mode\":\"%s\","
            "\"ip\":\"%s\",\"gateway\":\"%s\",\"monitor_ip\":\"%s\","
            "\"priority\":%d,\"backup\":%s,\"nat\":%s,"
            "\"status\":\"%s\",\"active\":%s,\"rtt_ms\":%.2f,"
            "\"loss_pct\":%d,\"probes\":%lu,\"failures\":%lu,"
            "\"last_change\":%ld}",
            i ? "," : "", i, w->ifname,
            w->mode == WAN_DHCP ? "dhcp" : w->mode == WAN_STATIC ? "static"
              : w->mode == WAN_PPPOE ? "pppoe" : "disabled",
            fx_ip_str(w->ip, ip, sizeof(ip)),
            fx_ip_str(w->gateway, gw, sizeof(gw)),
            w->monitor_ip, w->failover_priority,
            w->is_backup ? "true" : "false",
            w->nat_enabled ? "true" : "false",
            s ? gwmon_status_str(s->status) : "unknown",
            (i == active) ? "true" : "false",
            s ? s->avg_rtt_ms : 0.0,
            s ? s->loss_pct : 0,
            s ? s->probes : 0UL,
            s ? s->failures : 0UL,
            s ? (long)s->last_change : 0L);
    }
    pthread_mutex_unlock(&g_netconf.lock);
    o += (size_t)snprintf(b + o, cap - o, "]}");

    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b);
}

/* ---- GET /api/vpn ----
 * Secrets never appear here. The interface private key is shown as a
 * fingerprint, pre-shared keys as a yes/no, and IPsec PSKs not at all.
 * Public keys are not secret and are shown in full, because an operator
 * needs to read them off to configure the far end.
 */
static void api_vpn(int fd) {
    size_t cap = 64 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t n = 0;
    char esc[VLAN_DESC_LEN * 2], nb[64], fp[32], a[INET_ADDRSTRLEN];

    /* The temporary is underscored: an argument named `w` would otherwise be
     * captured by this declaration rather than referring to the caller's. */
    #define APP(...) do { \
        int _apw = snprintf(b + n, cap - n, __VA_ARGS__); \
        if (_apw < 0 || (size_t)_apw >= cap - n) { goto done; } \
        n += (size_t)_apw; } while (0)

    pthread_mutex_lock(&g_vpn.lock);

    APP("{\"wireguard\":[");
    for (int i = 0; i < g_vpn.wg_count; i++) {
        wg_iface_t *w = &g_vpn.wg[i];
        json_escape(w->description, esc, sizeof(esc));
        APP("%s{\"ifname\":\"%s\",\"enabled\":%s,\"listen_port\":%u,"
            "\"address\":\"%s\",\"cidr\":%d,\"mtu\":%d,\"zone\":\"%s\","
            "\"public_key\":\"%s\",\"key_fingerprint\":\"%s\","
            "\"description\":\"%s\"}",
            i ? "," : "", w->ifname, w->enabled ? "true" : "false",
            w->listen_port, fx_ip_str(w->address, a, sizeof(a)),
            fx_netmask_to_cidr(w->netmask), w->mtu, zone_name(w->zone),
            w->public_key,
            wg_key_fingerprint(w->private_key, fp, sizeof(fp)), esc);
    }

    APP("],\"peers\":[");
    for (int i = 0; i < g_vpn.peer_count; i++) {
        wg_peer_t *p = &g_vpn.peers[i];
        json_escape(p->description, esc, sizeof(esc));
        APP("%s{\"name\":\"%s\",\"interface\":\"%s\",\"enabled\":%s,"
            "\"public_key\":\"%s\",\"has_psk\":%s,\"zone\":\"%s\","
            "\"endpoint\":\"%s\",\"endpoint_port\":%u,\"keepalive\":%d,"
            "\"roaming\":%s,\"rx_bytes\":%lu,\"tx_bytes\":%lu,"
            "\"last_handshake\":%ld,\"allowed_ips\":[",
            i ? "," : "", p->name, p->ifname, p->enabled ? "true" : "false",
            p->public_key, p->preshared_key[0] ? "true" : "false",
            zone_name(p->zone), p->endpoint_host, p->endpoint_port,
            p->keepalive, p->endpoint_host[0] ? "false" : "true",
            p->rx_bytes, p->tx_bytes, (long)p->last_handshake);
        for (int k = 0; k < p->allowed_count; k++)
            APP("%s\"%s\"", k ? "," : "",
                fx_cidr_str(p->allowed[k].ip, p->allowed[k].mask, nb, sizeof(nb)));
        APP("]}");
    }

    APP("],\"ipsec\":[");
    char lb[64], rb[64];
    for (int i = 0; i < g_vpn.tunnel_count; i++) {
        ipsec_tunnel_t *t = &g_vpn.tunnels[i];
        json_escape(t->description, esc, sizeof(esc));
        APP("%s{\"name\":\"%s\",\"enabled\":%s,\"remote_host\":\"%s\","
            "\"local_subnet\":\"%s\",\"remote_subnet\":\"%s\","
            "\"version\":\"%s\",\"ike_proposal\":\"%s\","
            "\"esp_proposal\":\"%s\",\"dpd\":%s,\"zone\":\"%s\","
            "\"description\":\"%s\"}",
            i ? "," : "", t->name, t->enabled ? "true" : "false",
            t->remote_host,
            fx_cidr_str(t->local_subnet, t->local_mask, lb, sizeof(lb)),
            fx_cidr_str(t->remote_subnet, t->remote_mask, rb, sizeof(rb)),
            ike_version_str(t->version), t->ike_proposal, t->esp_proposal,
            t->dpd ? "true" : "false", zone_name(t->zone), esc);
    }
    APP("]}");

    pthread_mutex_unlock(&g_vpn.lock);
    #undef APP
    blockpage_send(fd, "200 OK", "application/json", b, n);
    free(b);
    return;

done:
    pthread_mutex_unlock(&g_vpn.lock);
    send_err(fd, "500 Internal Server Error", "VPN response too large");
    free(b);
}

/* ---- POST /api/vpn/keygen ----
 * Returns a fresh keypair for the operator to hand to a peer. The private
 * half is returned exactly once and is not stored: whoever asked for it is
 * the only one who will ever see it.
 */
static void api_vpn_keygen(int fd) {
    char priv[WG_KEY_B64_LEN], pub[WG_KEY_B64_LEN];
    if (wg_generate_keypair(priv, pub) != 0) {
        send_err(fd, "500 Internal Server Error", "key generation failed");
        return;
    }
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"private_key\":\"%s\",\"public_key\":\"%s\","
             "\"note\":\"the private key is shown once and not stored\"}",
             priv, pub);
    explicit_bzero(priv, sizeof(priv));
    send_json(fd, "200 OK", buf);
    explicit_bzero(buf, sizeof(buf));
}

/* ---- POST /api/vpn/peers ---- */
static void api_peer_create(int fd, const char *body, size_t len) {
    wg_peer_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = true;
    p.zone    = ZONE_VPN;

    char name[VPN_NAME_LEN], key[WG_KEY_B64_LEN], allowed[1024];
    char ifn[IFNAME_LEN], zbuf[32], ep[VPN_HOST_LEN], desc[VLAN_DESC_LEN];
    long num;

    if (!json_str(body, len, "name", name, sizeof(name)) || !name[0]) {
        send_err(fd, "400 Bad Request", "name is required");
        return;
    }
    if (!json_str(body, len, "public_key", key, sizeof(key))) {
        send_err(fd, "400 Bad Request", "public_key is required");
        return;
    }
    if (!wg_key_valid(key)) {
        send_err(fd, "422 Unprocessable Entity",
                 "public_key must be 44 base64 characters");
        return;
    }
    if (!json_str(body, len, "allowed_ips", allowed, sizeof(allowed))) {
        send_err(fd, "400 Bad Request", "allowed_ips is required");
        return;
    }

    memcpy(p.name, name, sizeof(name));
    memcpy(p.public_key, key, sizeof(key));
    snprintf(p.ifname, IFNAME_LEN, "%s",
             json_str(body, len, "interface", ifn, sizeof(ifn)) ? ifn : "wg0");
    if (json_str(body, len, "description", desc, sizeof(desc)))
        memcpy(p.description, desc, sizeof(desc));
    if (json_str(body, len, "zone", zbuf, sizeof(zbuf))) {
        zone_t z = zone_from(zbuf);
        if (z == ZONE_MAX) {
            send_err(fd, "422 Unprocessable Entity", "unknown zone");
            return;
        }
        p.zone = z;
    }
    if (json_str(body, len, "preshared_key", key, sizeof(key))) {
        if (!wg_key_valid(key)) {
            send_err(fd, "422 Unprocessable Entity", "preshared_key is malformed");
            return;
        }
        memcpy(p.preshared_key, key, sizeof(key));
    }
    if (json_str(body, len, "endpoint", ep, sizeof(ep))) {
        char *colon = strrchr(ep, ':');
        if (colon) { *colon = '\0'; p.endpoint_port = (uint16_t)atoi(colon + 1); }
        snprintf(p.endpoint_host, VPN_HOST_LEN, "%s", ep);
        if (!p.endpoint_port) p.endpoint_port = 51820;
    }
    if (json_int(body, len, "keepalive", &num)) p.keepalive = (int)num;

    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", allowed);
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",", &save);
         tok && p.allowed_count < WG_ALLOWED_MAX;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        uint32_t ip4 = 0, m = 0;
        fx_parse_cidr(tok, &ip4, &m);
        if (!ip4 && !m) continue;
        p.allowed[p.allowed_count].ip   = ip4;
        p.allowed[p.allowed_count].mask = m;
        p.allowed_count++;
    }
    if (!p.allowed_count) {
        send_err(fd, "422 Unprocessable Entity",
                 "allowed_ips must list at least one address or CIDR");
        return;
    }

    if (vpn_add_peer(&g_vpn, &p) != 0) {
        send_err(fd, "409 Conflict", "that peer already exists, or the table is full");
        return;
    }

    /* Validate the whole configuration; back the peer out if it does not fit. */
    cfg_validate_t res;
    pthread_mutex_lock(&g_vlan.lock);
    pthread_mutex_lock(&g_netconf.lock);
    int bad = firex_validate(&g_vlan, &g_netconf, &g_blockpage, &g_vpn, &res);
    pthread_mutex_unlock(&g_netconf.lock);
    pthread_mutex_unlock(&g_vlan.lock);

    if (bad != 0) {
        vpn_remove_peer(&g_vpn, p.name);
        send_err(fd, "422 Unprocessable Entity", res.error);
        return;
    }

    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"staged\",\"name\":\"%s\",\"zone\":\"%s\","
             "\"hint\":\"save a revision, then apply\"}",
             p.name, zone_name(p.zone));
    send_json(fd, "200 OK", buf);
    explicit_bzero(&p, sizeof(p));
}

/* ---- DELETE /api/vpn/peers/<name> ---- */
static void api_peer_delete(int fd, const char *name) {
    if (vpn_remove_peer(&g_vpn, name) != 0) {
        send_err(fd, "404 Not Found", "no such peer");
        return;
    }
    send_json(fd, "200 OK", "{\"status\":\"staged\",\"deleted\":true}");
}

/* ---- GET /api/state : the kernel's connection table ---- */
static void api_state(int fd) {
    ct_entry_t *e = calloc(CT_MAX_ENTRIES, sizeof(*e));
    if (!e) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }

    ct_stats_t st;
    int n = ct_read(e, CT_MAX_ENTRIES, &st);

    size_t cap = 512 * 1024;
    char *b = malloc(cap);
    if (!b) { free(e); send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char sa[INET_ADDRSTRLEN], da[INET_ADDRSTRLEN], esc[512];

    json_escape(st.source_detail, esc, sizeof(esc));
    o += (size_t)snprintf(b + o, cap - o,
             "{\"source\":\"%s\",\"detail\":\"%s\",\"count\":%u,"
             "\"max\":%u,\"listed\":%d,\"entries\":[",
             ct_source_str(st.source), esc, st.count, st.max, st.listed);

    for (int i = 0; i < n && o < cap - 512; i++) {
        o += (size_t)snprintf(b + o, cap - o,
             "%s{\"proto\":\"%s\",\"src\":\"%s\",\"sport\":%u,"
             "\"dst\":\"%s\",\"dport\":%u,\"state\":\"%s\","
             "\"packets\":%llu,\"bytes\":%llu,\"rx_packets\":%llu,"
             "\"rx_bytes\":%llu,\"ttl\":%d,\"assured\":%s}",
             i ? "," : "", e[i].proto,
             fx_ip_str(e[i].src, sa, sizeof(sa)), e[i].sport,
             fx_ip_str(e[i].dst, da, sizeof(da)), e[i].dport,
             e[i].state, (unsigned long long)e[i].packets,
             (unsigned long long)e[i].bytes,
             (unsigned long long)e[i].rx_packets,
             (unsigned long long)e[i].rx_bytes,
             e[i].ttl, e[i].assured ? "true" : "false");
    }
    o += (size_t)snprintf(b + o, cap - o, "]}");

    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b);
    free(e);
}

/* ---- GET /api/history : the counter ring, oldest first ---- */
static void api_history(int fd) {
    hist_sample_t *s = calloc(HIST_SAMPLES, sizeof(*s));
    if (!s) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    int n = hist_snapshot(&g_hist, s, HIST_SAMPLES);

    size_t cap = (size_t)n * 256 + 4096;
    char *b = malloc(cap);
    if (!b) { free(s); send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;

    o += (size_t)snprintf(b + o, cap - o,
             "{\"interval\":%d,\"capacity\":%d,\"samples\":[",
             g_hist.interval_sec, HIST_SAMPLES);

    for (int i = 0; i < n && o < cap - 256; i++) {
        o += (size_t)snprintf(b + o, cap - o,
             "%s{\"t\":%ld,\"packets\":%u,\"allowed\":%u,\"blocked\":%u,"
             "\"ivr_allowed\":%u,\"ivr_denied\":%u,\"pages\":%u,"
             "\"sched_skipped\":%u,\"tag_violations\":%u,\"states\":%u,"
             "\"wan0_rtt\":%.1f,\"wan1_rtt\":%.1f,"
             "\"wan0_loss\":%u,\"wan1_loss\":%u,\"active_wan\":%d}",
             i ? "," : "", (long)s[i].when, s[i].packets, s[i].allowed,
             s[i].blocked, s[i].ivr_allowed, s[i].ivr_denied,
             s[i].pages_served, s[i].sched_skipped, s[i].tag_violations,
             s[i].ct_count,
             s[i].wan_rtt_x10[0] / 10.0, s[i].wan_rtt_x10[1] / 10.0,
             s[i].wan_loss[0], s[i].wan_loss[1], s[i].active_wan);
    }
    o += (size_t)snprintf(b + o, cap - o, "]}");

    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b);
    free(s);
}

/* ---- GET /api/capture ---- */
static void api_capture_status(int fd) {
    capture_ctx_t c;
    capture_status(&g_capture, &c);

    char esc[320], host[INET_ADDRSTRLEN], buf[1024];
    json_escape(c.error, esc, sizeof(esc));
    snprintf(buf, sizeof(buf),
             "{\"state\":\"%s\",\"error\":\"%s\",\"packets\":%d,"
             "\"seen\":%d,\"bytes\":%llu,\"started\":%ld,\"finished\":%ld,"
             "\"iface\":\"%s\",\"host\":\"%s\",\"port\":%u,"
             "\"proto\":%u,\"max_packets\":%d,\"max_seconds\":%d,"
             "\"snaplen\":%d,\"downloadable\":%s,"
             "\"caps\":{\"packets\":%d,\"seconds\":%d,\"bytes\":%lu}}",
             capture_state_str(c.state), esc, c.packets, c.seen,
             (unsigned long long)c.bytes, (long)c.started, (long)c.finished,
             c.req.ifname, fx_ip_str(c.req.host, host, sizeof(host)),
             c.req.port, c.req.proto, c.req.max_packets, c.req.max_seconds,
             c.req.snaplen,
             (c.state == CAP_DONE && c.packets > 0) ? "true" : "false",
             CAP_MAX_PACKETS, CAP_MAX_SECONDS, (unsigned long)CAP_MAX_BYTES);
    send_json(fd, "200 OK", buf);
}

/* ---- POST /api/capture/start ---- */
static void api_capture_start(int fd, const fx_session_t *s,
                              const char *body, size_t len) {
    capture_req_t r;
    memset(&r, 0, sizeof(r));

    char sbuf[128];
    long num;

    if (!json_str(body, len, "iface", sbuf, IFNAME_LEN)) {
        send_err(fd, "400 Bad Request", "iface is required");
        return;
    }
    memcpy(r.ifname, sbuf, IFNAME_LEN);

    if (json_str(body, len, "host", sbuf, sizeof(sbuf)) && sbuf[0]) {
        struct in_addr ia;
        if (inet_pton(AF_INET, sbuf, &ia) != 1) {
            send_err(fd, "422 Unprocessable Entity",
                     "host must be an IPv4 address");
            return;
        }
        r.host = ia.s_addr;
    }
    if (json_int(body, len, "port", &num)) {
        if (num < 0 || num > 65535) {
            send_err(fd, "422 Unprocessable Entity", "port is out of range");
            return;
        }
        r.port = (uint16_t)num;
    }
    if (json_str(body, len, "proto", sbuf, sizeof(sbuf))) {
        if      (!strcasecmp(sbuf, "tcp"))  r.proto = 6;
        else if (!strcasecmp(sbuf, "udp"))  r.proto = 17;
        else if (!strcasecmp(sbuf, "icmp")) r.proto = 1;
        else if (strcasecmp(sbuf, "any") != 0 && sbuf[0]) {
            send_err(fd, "422 Unprocessable Entity",
                     "proto must be tcp, udp, icmp or any");
            return;
        }
    }
    if (json_int(body, len, "max_packets", &num)) r.max_packets = (int)num;
    if (json_int(body, len, "max_seconds", &num)) r.max_seconds = (int)num;
    if (json_int(body, len, "snaplen", &num))     r.snaplen     = (int)num;

    if (capture_start(&g_capture, &r, g_capture_dir) != 0) {
        capture_ctx_t c;
        capture_status(&g_capture, &c);
        send_err(fd, "409 Conflict", c.error[0] ? c.error : "capture failed");
        return;
    }

    printf("[%s] capture started by %s\n", BRAND_PRODUCT, s->user);
    api_capture_status(fd);
}

static void api_capture_stop(int fd) {
    capture_stop(&g_capture);
    api_capture_status(fd);
}

/* ---- GET /api/capture/download ----
 * Streamed rather than buffered: a capture can be tens of megabytes, and
 * holding one in memory to hand it over would be the wrong shape entirely.
 */
static void api_capture_download(int fd) {
    capture_ctx_t c;
    capture_status(&g_capture, &c);

    if (c.state != CAP_DONE || c.packets <= 0) {
        send_err(fd, "404 Not Found", "no completed capture to download");
        return;
    }

    FILE *f = fopen(c.path, "rb");
    if (!f) { send_err(fd, "404 Not Found", "the capture file is gone"); return; }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    if (size < 0) { fclose(f); send_err(fd, "500 Internal Server Error", "unreadable"); return; }

    char hdr[512];
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/vnd.tcpdump.pcap\r\n"
        "Content-Length: %ld\r\n"
        "Content-Disposition: attachment; filename=\"firex-capture.pcap\"\r\n"
        "X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n"
        "Connection: close\r\n\r\n", size);

    /* bp_write, not write: on the console listener this socket is inside a
     * TLS session, and a raw write would inject plaintext into the record
     * stream and break the connection mid-download. */
    if (bp_write(fd, hdr, (size_t)hl) > 0) {
        char buf[65536];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
            if (bp_write(fd, buf, n) < 0) break;
    }
    fclose(f);
}

/* ---- GET /api/telemetry ---- */
static void api_telemetry(int fd) {
    pthread_mutex_lock(&g_telemetry.lock);
    telemetry_ctx_t t = g_telemetry;
    pthread_mutex_unlock(&g_telemetry.lock);

    char buf[768];
    snprintf(buf, sizeof(buf),
        "{\"syslog\":{\"configured\":%s,\"host\":\"%s\",\"port\":%u,"
        "\"proto\":\"%s\",\"connected\":%s,\"sent\":%lu,\"dropped\":%lu},"
        "\"netflow\":{\"configured\":%s,\"host\":\"%s\",\"port\":%u,"
        "\"interval\":%d,\"connected\":%s,\"flows\":%lu,\"packets\":%lu}}",
        telemetry_has_syslog(&t) ? "true" : "false",
        t.cfg.syslog_host, t.cfg.syslog_port,
        t.cfg.syslog_tcp ? "tcp" : "udp",
        t.syslog_fd >= 0 ? "true" : "false",
        t.syslog_sent, t.syslog_dropped,
        telemetry_has_netflow(&t) ? "true" : "false",
        t.cfg.netflow_host, t.cfg.netflow_port, t.cfg.netflow_interval,
        t.netflow_fd >= 0 ? "true" : "false",
        t.flows_sent, t.netflow_packets);
    send_json(fd, "200 OK", buf);
}

/* ═══════════════════════ captive portal ═══════════════════════ */

/*
 * Reads one field out of an application/x-www-form-urlencoded body. The
 * portal login form is submitted by a browser with no script, so it arrives
 * form-encoded rather than as JSON.
 */
static bool form_get(const char *body, size_t len, const char *key,
                     char *out, size_t outlen) {
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen + 1 <= len; i++) {
        if (i && body[i-1] != '&') continue;
        if (memcmp(body + i, key, klen) || body[i + klen] != '=') continue;

        size_t j = i + klen + 1, o = 0;
        while (j < len && body[j] != '&') {
            char c = body[j];
            if (c == '+') c = ' ';
            else if (c == '%' && j + 2 < len) {
                char hex[3] = { body[j+1], body[j+2], 0 };
                char *end = NULL;
                long v = strtol(hex, &end, 16);
                if (end == hex + 2) { c = (char)v; j += 2; }
            }
            if (o + 1 >= outlen) return false;   /* reject, do not truncate */
            out[o++] = c;
            j++;
        }
        out[o] = '\0';
        return true;
    }
    return false;
}

/* Which VLAN an address belongs to, for the session record. */
static uint16_t vlan_of(uint32_t ip) {
    uint16_t vid = 0;
    pthread_mutex_lock(&g_vlan.lock);
    for (int i = 0; i < g_vlan.vlan_count; i++) {
        vlan_config_t *c = &g_vlan.vlans[i];
        if (c->enabled && c->subnet && c->netmask &&
            (ip & c->netmask) == (c->subnet & c->netmask)) {
            vid = c->vlan_id;
            break;
        }
    }
    pthread_mutex_unlock(&g_vlan.lock);
    return vid;
}

static void portal_page(int fd, const char *message, const char *redirect) {
    size_t cap = 32 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }

    int n = portal_render_login(&g_portal, b, cap, message, redirect);
    if (n < 0) { free(b); send_err(fd, "500 Internal Server Error", "render failed"); return; }

    /* 200, not a redirect: captive-portal detectors look for content that is
     * not the 204 they asked for. */
    blockpage_send(fd, "200 OK", "text/html; charset=utf-8", b, (size_t)n);
    free(b);
}

static void portal_success(int fd, const portal_session_t *sess) {
    size_t cap = 16 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }

    int n = portal_render_success(&g_portal, sess, b, cap);
    if (n < 0) { free(b); send_err(fd, "500 Internal Server Error", "render failed"); return; }
    blockpage_send(fd, "200 OK", "text/html; charset=utf-8", b, (size_t)n);
    free(b);
}

static void portal_do_login(int fd, uint32_t peer, const char *body, size_t len) {
    char user[PORTAL_USER_LEN] = "", pass[256] = "";
    char voucher[PORTAL_CODE_LEN] = "", redirect[512] = "";

    form_get(body, len, "username", user, sizeof(user));
    form_get(body, len, "password", pass, sizeof(pass));
    form_get(body, len, "voucher",  voucher, sizeof(voucher));
    form_get(body, len, "redirect", redirect, sizeof(redirect));

    char why[192] = "";
    int rc = portal_login(&g_portal, peer, vlan_of(peer), user, pass, voucher,
                          why, sizeof(why));
    explicit_bzero(pass, sizeof(pass));

    if (rc != 0) {
        portal_page(fd, why[0] ? why : "Could not sign you in.", redirect);
        return;
    }

    portal_session_t sess;
    if (portal_session(&g_portal, peer, &sess)) portal_success(fd, &sess);
    else portal_page(fd, "Session could not be established.", redirect);
}

/* Returns 1 when this request was a portal one and has been answered. */
static int portal_route(int fd, const char *method, const char *path,
                        uint32_t peer, const char *body, size_t body_len) {
    if (!g_portal.cfg.enabled) return 0;

    /*
     * The probe URLs every operating system fetches to decide whether it is
     * behind a captive portal. Answering them with the login page is what
     * makes the "Sign in to network" notification appear.
     */
    static const char *PROBES[] = {
        "/generate_204", "/gen_204", "/hotspot-detect.html",
        "/library/test/success.html", "/ncsi.txt", "/connecttest.txt",
        "/canonical.html", "/success.txt", NULL
    };

    bool is_probe = false;
    for (int i = 0; PROBES[i]; i++)
        if (!strcmp(path, PROBES[i])) { is_probe = true; break; }

    if (!is_probe && strncmp(path, "/portal", 7) != 0) return 0;

    if (!strcmp(path, "/portal/logout")) {
        portal_logout(&g_portal, peer);
        portal_page(fd, "You have been signed out.", "");
        return 1;
    }

    if (!strcmp(path, "/portal/login") && !strcmp(method, "POST")) {
        portal_do_login(fd, peer, body, body_len);
        return 1;
    }

    portal_session_t sess;
    if (portal_session(&g_portal, peer, &sess)) {
        portal_success(fd, &sess);
        return 1;
    }
    portal_page(fd, "", path);
    return 1;
}

/* ---- GET /api/portal ---- */
static void api_portal(int fd) {
    portal_session_t *sess = calloc(PORTAL_MAX_SESSIONS, sizeof(*sess));
    portal_voucher_t *vs   = calloc(PORTAL_MAX_VOUCHERS, sizeof(*vs));
    if (!sess || !vs) {
        free(sess); free(vs);
        send_err(fd, "500 Internal Server Error", "out of memory");
        return;
    }
    int ns = portal_snapshot(&g_portal, sess, PORTAL_MAX_SESSIONS);
    int nv = portal_voucher_snapshot(&g_portal, vs, PORTAL_MAX_VOUCHERS);

    size_t cap = 256 * 1024;
    char *b = malloc(cap);
    if (!b) { free(sess); free(vs); send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char a[INET_ADDRSTRLEN], esc[256];

    json_escape(g_portal.cfg.terms, esc, sizeof(esc));
    o += (size_t)snprintf(b + o, cap - o,
        "{\"enabled\":%s,\"auth\":\"%s\",\"session_minutes\":%d,"
        "\"idle_minutes\":%d,\"terms\":\"%s\","
        "\"radius\":{\"configured\":%s,\"host\":\"%s\",\"port\":%u},"
        "\"stats\":{\"ok\":%lu,\"failed\":%lu,\"expired\":%lu},"
        "\"sessions\":[",
        g_portal.cfg.enabled ? "true" : "false",
        portal_auth_name(g_portal.cfg.auth),
        g_portal.cfg.session_minutes, g_portal.cfg.idle_minutes, esc,
        g_portal.cfg.radius_host[0] ? "true" : "false",
        g_portal.cfg.radius_host, g_portal.cfg.radius_port,
        g_portal.logins_ok, g_portal.logins_failed, g_portal.expired);

    for (int i = 0; i < ns && o < cap - 512; i++) {
        json_escape(sess[i].user, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"ip\":\"%s\",\"user\":\"%s\",\"vlan_id\":%u,"
            "\"started\":%ld,\"last_seen\":%ld,\"expires\":%ld,"
            "\"voucher\":\"%s\"}",
            i ? "," : "", fx_ip_str(sess[i].ip, a, sizeof(a)), esc,
            sess[i].vlan_id, (long)sess[i].started, (long)sess[i].last_seen,
            (long)sess[i].expires, sess[i].voucher);
    }

    o += (size_t)snprintf(b + o, cap - o, "],\"vouchers\":[");
    for (int i = 0; i < nv && o < cap - 512; i++) {
        json_escape(vs[i].note, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"code\":\"%s\",\"minutes\":%d,\"created\":%ld,"
            "\"first_used\":%ld,\"used\":%s,\"enabled\":%s,"
            "\"note\":\"%s\"}",
            i ? "," : "", vs[i].code, vs[i].minutes, (long)vs[i].created,
            (long)vs[i].first_used, vs[i].used ? "true" : "false",
            vs[i].enabled ? "true" : "false", esc);
    }
    o += (size_t)snprintf(b + o, cap - o, "]}");

    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b); free(sess); free(vs);
}

static void api_portal_vouchers(int fd, const char *body, size_t len) {
    long count = 10, minutes = 1440;
    char note[64] = "";
    json_int(body, len, "count", &count);
    json_int(body, len, "minutes", &minutes);
    json_str(body, len, "note", note, sizeof(note));

    if (count < 1 || count > 200) {
        send_err(fd, "422 Unprocessable Entity", "count must be 1-200");
        return;
    }
    if (minutes < 1 || minutes > 10080) {
        send_err(fd, "422 Unprocessable Entity",
                 "minutes must be 1-10080 (one week)");
        return;
    }

    int made = portal_generate_vouchers(&g_portal, (int)count, (int)minutes,
                                        note[0] ? note : "generated");
    if (made <= 0) {
        send_err(fd, "409 Conflict", "the voucher table is full");
        return;
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"status\":\"created\",\"count\":%d}", made);
    send_json(fd, "200 OK", buf);
}

static void api_portal_kick(int fd, const char *ipstr) {
    struct in_addr ia;
    if (inet_pton(AF_INET, ipstr, &ia) != 1) {
        send_err(fd, "400 Bad Request", "not an IPv4 address");
        return;
    }
    portal_logout(&g_portal, ia.s_addr);
    send_json(fd, "200 OK", "{\"status\":\"disconnected\"}");
}

/* ---- GET /api/shaping : status plus the exact tc plan ---- */
static void api_shaping(int fd) {
    shaper_plan_t *plan = calloc(1, sizeof(*plan));
    if (!plan) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    shaper_plan(&g_netconf.shaping, &g_vlan, &g_netconf, plan);

    size_t cap = 128 * 1024;
    char *b = malloc(cap);
    if (!b) { free(plan); send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char esc[SHAPER_CMD_LEN * 2];

    shaper_cfg_t *c = &g_netconf.shaping;
    json_escape(g_shaper.last_error, esc, sizeof(esc));
    o += (size_t)snprintf(b + o, cap - o,
        "{\"enabled\":%s,\"applied\":%s,\"qdisc\":\"%s\","
        "\"wan_up_mbps\":%d,\"wan_down_mbps\":%d,\"ecn\":%s,"
        "\"ingress_shaping\":%s,\"codel_target_ms\":%d,"
        "\"codel_interval_ms\":%d,\"classes\":%d,\"failures\":%u,"
        "\"error\":\"%s\",\"vlans\":[",
        c->enabled ? "true" : "false", g_shaper.applied ? "true" : "false",
        qdisc_name(c->qdisc), c->wan_up_mbps, c->wan_down_mbps,
        c->ecn ? "true" : "false", c->ingress_shaping ? "true" : "false",
        c->codel_target_ms ? c->codel_target_ms : 5,
        c->codel_interval_ms ? c->codel_interval_ms : 100,
        g_shaper.classes, g_shaper.failures, esc);

    pthread_mutex_lock(&g_vlan.lock);
    int first = 1;
    for (int i = 0; i < g_vlan.vlan_count && o < cap - 512; i++) {
        vlan_config_t *vl = &g_vlan.vlans[i];
        if (!vl->bandwidth_up_mbps && !vl->bandwidth_down_mbps) continue;
        json_escape(vl->name, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"vlan_id\":%u,\"name\":\"%s\",\"up_mbps\":%d,"
            "\"down_mbps\":%d,\"priority\":%u,\"classid\":%d}",
            first ? "" : ",", vl->vlan_id, esc, vl->bandwidth_up_mbps,
            vl->bandwidth_down_mbps, vl->priority,
            shaper_classid_for(&g_vlan, vl->vlan_id));
        first = 0;
    }
    pthread_mutex_unlock(&g_vlan.lock);

    o += (size_t)snprintf(b + o, cap - o, "],\"plan\":[");
    for (int i = 0; i < plan->count && o < cap - SHAPER_CMD_LEN * 2; i++) {
        json_escape(plan->cmd[i], esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o, "%s\"%s\"", i ? "," : "", esc);
    }
    o += (size_t)snprintf(b + o, cap - o, "],\"plan_count\":%d}", plan->count);

    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b);
    free(plan);
}

/* ═══════════════════════ threat layer ═══════════════════════ */

/* ---- GET /api/threat : signatures, feeds and offenders ---- */

/* ═══ Appliance identity ══════════════════════════════════════════════
 *
 * What the console needs to label itself, plus the one fact the air gap
 * depends on: whether the clock can be trusted. A scheduled gap is
 * decided entirely by local time, so "the clock is not synchronised" is
 * a security state, not a cosmetic detail, and it belongs where the
 * operator can see it.
 */
static void api_system(int fd) {
    char host[128] = "";
    if (gethostname(host, sizeof(host) - 1) != 0) snprintf(host, sizeof(host), "unknown");

    long uptime = 0;
    FILE *f = fopen("/proc/uptime", "r");
    if (f) { double u = 0; if (fscanf(f, "%lf", &u) == 1) uptime = (long)u; fclose(f); }

    /*
     * adjtimex() reports the kernel's own view: TIME_ERROR means nothing
     * is disciplining the clock. That is more honest than asking a
     * particular NTP daemon, which may not be the one in use.
     */
    bool synced = false;
    struct timex tx;
    memset(&tx, 0, sizeof(tx));
    int st = adjtimex(&tx);
    if (st >= 0 && st != TIME_ERROR) synced = true;

    /* The air gap asks this of itself every tick; keep it current.
     * Through the setter, which takes the lock -- writing the field
     * directly from this thread was a race with the tick that reads it. */
    airgap_set_time_synced(&g_airgap, synced);

    char esc[160];
    json_escape(host, esc, sizeof(esc));

    /*
     * The console reports its own transport. An operator looking at a
     * management page has no way to tell from the page whether it arrived
     * encrypted, and "it is on 8443" is not an answer -- that was true for
     * the whole period this console served in the clear.
     */
    const bool tls_on = blockpage_tls_active(&g_blockpage);
    char fp[128];
    json_escape(tls_on ? g_blockpage.tls_fingerprint : "", fp, sizeof(fp));

    char out[1024];
    snprintf(out, sizeof(out),
        "{\"product\":\"%s\",\"vendor\":\"%s\",\"version\":\"%s\","
        "\"edition\":\"%s\",\"hostname\":\"%s\",\"uptime\":%ld,"
        "\"time\":%ld,\"time_synced\":%s,"
        "\"tls\":%s,\"tls_fingerprint\":\"%s\","
        "\"tls_handshake_fail\":%lu,\"unsaved\":%u,"
        "\"conns\":{\"console\":%d,\"portal\":%d,\"limit\":%d,"
        "\"refused\":%lu}}",
        BRAND_PRODUCT, BRAND_VENDOR, BRAND_VERSION, BRAND_EDITION,
        esc, uptime, (long)time(NULL), synced ? "true" : "false",
        tls_on ? "true" : "false", fp, g_blockpage.tls_handshake_fail,
        unsaved(),
        g_blockpage.conns_admin, g_blockpage.conns_portal,
        BP_MAX_CONNS, g_blockpage.conns_refused);
    send_json(fd, "200 OK", out);
}

/* ═══ Interfaces ═══════════════════════════════════════════════════════
 *
 * Reported from the kernel rather than from the configuration, so the
 * page shows what the ports are doing and not what they were told to do.
 */
static void api_interfaces(int fd) {
    netif_t list[NETIF_MAX];
    int n = netif_list(list, NETIF_MAX);

    size_t cap = 96 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char esc[128];

    o += (size_t)snprintf(b + o, cap - o, "{\"interfaces\":[");
    for (int i = 0; i < n && o < cap - 768; i++) {
        netif_t *f = &list[i];

        /* The port's role comes from the segmentation config: which VLAN
         * has it, and therefore which zone it sits in. */
        const char *zone = "";
        int pvid = 0;
        port_config_t *pc = port_get(&g_vlan, f->name);
        if (pc) { zone = zone_name(pc->zone); pvid = pc->pvid; }

        bool is_wan = false;
        for (int w = 0; w < g_netconf.wan_count; w++)
            if (!strcmp(g_netconf.wan[w].ifname, f->name)) { is_wan = true; break; }

        json_escape(f->name, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"name\":\"%s\",\"kind\":\"%s\",\"mac\":\"%s\",\"ipv4\":\"%s\","
            "\"netmask\":\"%s\",\"driver\":\"%s\",\"admin_up\":%s,\"carrier\":%s,"
            "\"oper\":\"%s\",\"mtu\":%d,\"speed\":%d,\"duplex\":\"%s\","
            "\"zone\":\"%s\",\"pvid\":%d,\"wan\":%s,"
            "\"rx_bytes\":%lu,\"tx_bytes\":%lu,\"rx_packets\":%lu,\"tx_packets\":%lu,"
            "\"rx_errors\":%lu,\"tx_errors\":%lu,\"rx_dropped\":%lu,\"tx_dropped\":%lu}",
            i ? "," : "", esc, netif_kind_name(f->kind), f->mac, f->ipv4,
            f->netmask, f->driver, f->admin_up ? "true" : "false",
            f->carrier ? "true" : "false", f->oper, f->mtu, f->speed_mbps,
            f->duplex, zone, pvid, is_wan ? "true" : "false",
            f->rx_bytes, f->tx_bytes, f->rx_packets, f->tx_packets,
            f->rx_errors, f->tx_errors, f->rx_dropped, f->tx_dropped);
    }
    o += (size_t)snprintf(b + o, cap - o, "],\"count\":%d}", n);
    send_json(fd, "200 OK", b);
    free(b);
}

static void api_interface_admin(int fd, const char *name,
                                const char *body, size_t len) {
    if (!netif_name_ok(name)) {
        send_err(fd, "400 Bad Request", "that is not a valid interface name");
        return;
    }
    bool want_up = false;
    if (!json_bool(body, len, "up", &want_up)) {
        send_err(fd, "400 Bad Request", "\"up\" must be true or false");
        return;
    }

    netif_t before;
    if (!netif_get(name, &before)) {
        send_err(fd, "404 Not Found", "no such interface");
        return;
    }

    /*
     * Refuse to take down the link the request arrived on. It is the
     * single most effective way to lock yourself out of an appliance, it
     * is always a mistake, and the operator cannot undo it from the page
     * that just disappeared.
     */
    if (!want_up) {
        port_config_t *pc = port_get(&g_vlan, name);
        if (pc && pc->zone == ZONE_MGMT) {
            send_err(fd, "409 Conflict",
                     "that port is in the management zone; taking it down "
                     "would end this session and cannot be undone from here");
            return;
        }
    }

    if (netif_set_admin(name, want_up) != 0) {
        audited(AUDIT_FAILED, "interface.admin", name,
                "could not bring the link %s: %s",
                want_up ? "up" : "down", strerror(errno));
        send_err(fd, "500 Internal Server Error",
                 errno == EPERM || errno == EACCES
                     ? "the daemon is not running with CAP_NET_ADMIN"
                     : "the kernel refused the change");
        return;
    }
    audited(AUDIT_OK, "interface.admin", name,
            "link brought %s (was %s)", want_up ? "up" : "down",
            before.admin_up ? "up" : "down");
    /* Not part of the saved configuration at all: this is an ioctl on a
     * kernel interface, and a restart re-applies whatever the config says.
     * Saying "persisted: false" here is accurate; offering to save it
     * would not be. */
    send_json(fd, "200 OK",
              "{\"ok\":true,\"persisted\":false,"
              "\"hint\":\"a link state set here lasts until the interface "
              "is reconfigured or the appliance restarts\"}");
}

/* ═══ Live malware protection ═════════════════════════════════════════ */

static void api_malware(int fd) {
    mw_event_t ev[64];
    int n = mw_recent(&g_malware, ev, 64);
    int flows = mw_active_flows(&g_malware);

    size_t cap = 64 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char esc[256], ctype[192], sip[INET_ADDRSTRLEN], dip[INET_ADDRSTRLEN];

    pthread_mutex_lock(&g_malware.lock);
    /* db_version is read out of the signature file, which may come from a
     * feed. Everything that crosses into JSON from outside gets escaped,
     * including the strings that "obviously" cannot contain a quote. */
    char dbv[128];
    json_escape(g_malware.db_version, dbv, sizeof(dbv));
    o += (size_t)snprintf(b + o, cap - o,
        "{\"enabled\":%s,\"block\":%s,\"hashes\":%d,\"patterns\":%d,"
        "\"db_version\":\"%s\",\"db_loaded\":%ld,"
        "\"objects\":%lu,\"bytes\":%lu,\"opaque\":%lu,\"detections\":%lu,"
        "\"blocked\":%lu,\"truncated\":%lu,\"partial\":%lu,\"flows_tracked\":%lu,"
        "\"flows_dropped\":%lu,\"flows_active\":%d,\"max_object\":%zu,",
        g_malware.enabled ? "true" : "false",
        g_malware.block ? "true" : "false",
        g_malware.hash_count, g_malware.pattern_count,
        dbv, (long)g_malware.db_loaded,
        g_malware.objects_scanned, g_malware.bytes_scanned,
        g_malware.bytes_opaque, g_malware.detections, g_malware.blocked,
        g_malware.truncated, g_malware.partial,
        g_malware.flows_tracked, g_malware.flows_dropped,
        flows, g_malware.max_object);
    pthread_mutex_unlock(&g_malware.lock);

    /*
     * COVERAGE, and it is not decoration.
     *
     * The scanner runs per segment: inspect.c scans a packet only when the
     * VLAN it belongs to has malware_scan set. "enabled: true" above is
     * therefore a statement about the engine, not about the network, and
     * reporting it on its own let the console say "Malware protection:
     * enabled, blocking" over an appliance on which no segment was being
     * scanned at all. That is not a cosmetic defect -- it is a control
     * reporting success it is not delivering, which is the same class of
     * fault as the air gap that never gated anything.
     *
     * So the console gets the number that is actually true: how many
     * segments are covered, and the names of the ones that are not.
     */
    int seg_total = 0, seg_on = 0;
    o += (size_t)snprintf(b + o, cap - o, "\"coverage\":{\"uncovered\":[");
    {
        int listed = 0;
        for (int i = 0; i < g_vlan.vlan_count && o < cap - 512; i++) {
            vlan_config_t *v = &g_vlan.vlans[i];
            if (!v->enabled) continue;
            seg_total++;
            if (v->malware_scan) { seg_on++; continue; }
            json_escape(v->name, esc, sizeof(esc));
            o += (size_t)snprintf(b + o, cap - o, "%s{\"vlan\":%u,\"name\":\"%s\"}",
                                  listed++ ? "," : "", v->vlan_id, esc);
        }
    }
    o += (size_t)snprintf(b + o, cap - o,
        "],\"segments\":%d,\"segments_scanned\":%d,"
        /*
         * Traffic that matches no configured segment is not scanned
         * either -- inspect.c needs a VLAN to read the flag from. Saying
         * so is the difference between a limitation and a surprise.
         */
        "\"unmatched_scanned\":false},\"events\":[",
        seg_total, seg_on);

    for (int i = 0; i < n && o < cap - 768; i++) {
        fx_ip_str(ev[i].src_ip, sip, sizeof(sip));
        fx_ip_str(ev[i].dst_ip, dip, sizeof(dip));
        json_escape(ev[i].name, esc, sizeof(esc));
        json_escape(ev[i].ctype, ctype, sizeof(ctype));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"when\":%ld,\"name\":\"%s\",\"sha256\":\"%s\",\"ctype\":\"%s\","
            "\"src\":\"%s\",\"dst\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
            "\"severity\":%u,\"source\":\"%s\",\"blocked\":%s,\"size\":%zu}",
            i ? "," : "", (long)ev[i].when, esc, ev[i].sha256, ctype, sip, dip,
            ev[i].src_port, ev[i].dst_port, ev[i].severity,
            mw_source_name(ev[i].source),
            ev[i].blocked ? "true" : "false", ev[i].size);
    }
    o += (size_t)snprintf(b + o, cap - o, "]}");
    send_json(fd, "200 OK", b);
    free(b);
}

static void api_malware_mode(int fd, const fx_session_t *s,
                             const char *body, size_t len) {
    bool en = false, bl = false;
    bool have_en = json_bool(body, len, "enabled", &en);
    bool have_bl = json_bool(body, len, "block",   &bl);
    if (!have_en && !have_bl) {
        send_err(fd, "400 Bad Request", "send \"enabled\" and/or \"block\"");
        return;
    }

    pthread_mutex_lock(&g_malware.lock);
    if (have_en) g_malware.enabled = en;
    if (have_bl) g_malware.block   = bl;
    bool now_en = g_malware.enabled, now_bl = g_malware.block;
    pthread_mutex_unlock(&g_malware.lock);

    g_netconf.malware.enabled = now_en;
    g_netconf.malware.block   = now_bl;

    audited(AUDIT_OK, "malware.mode",
            now_en ? (now_bl ? "blocking" : "detect-only") : "disabled",
            "scanner %s, %s", now_en ? "enabled" : "disabled",
            now_bl ? "blocking" : "detect-only");
    fprintf(stderr, "[%s] malware: %s/%s by %s\n", BRAND_PRODUCT,
            now_en ? "enabled" : "disabled",
            now_bl ? "blocking" : "detect-only", s ? s->user : "?");

    mark_unsaved();

    char out[256];
    snprintf(out, sizeof(out),
             "{\"enabled\":%s,\"block\":%s,\"persisted\":false,"
             "\"hint\":\"in effect now; POST /api/config/save to keep it "
             "across a restart\"}",
             now_en ? "true" : "false", now_bl ? "true" : "false");
    send_json(fd, "200 OK", out);
}

static void api_malware_reload(int fd) {
    if (!g_netconf.malware.db_path[0]) {
        send_err(fd, "409 Conflict", "no signature database is configured");
        return;
    }
    int n = mw_load_hashes(&g_malware, g_netconf.malware.db_path);
    if (n < 0) {
        send_err(fd, "500 Internal Server Error",
                 "the database could not be read; the previous one is still loaded");
        return;
    }
    audited(AUDIT_OK, "malware.reload", g_netconf.malware.db_path,
            "%d signature(s) loaded", n);

    char out[128];
    snprintf(out, sizeof(out), "{\"ok\":true,\"hashes\":%d}", n);
    send_json(fd, "200 OK", out);
}

/* ═══ Air gap ═════════════════════════════════════════════════════════ */

static void api_airgap(int fd) {
    ag_event_t ev[32];
    int n = airgap_recent(&g_airgap, ev, 32);

    size_t cap = 32 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char esc[256], days[32];

    pthread_mutex_lock(&g_airgap.lock);
    json_escape(g_airgap.state_reason, esc, sizeof(esc));
    o += (size_t)snprintf(b + o, cap - o,
        "{\"mode\":\"%s\",\"label\":\"%s\",\"open\":%s,\"reason\":\"%s\","
        "\"last_change\":%ld,\"next_change\":%ld,\"time_synced\":%s,"
        "\"require_time_sync\":%s,\"denied_in\":%lu,\"denied_out\":%lu,"
        "\"passed_in\":%lu,\"passed_out\":%lu,\"blocked_fetches\":%lu,"
        "\"windows\":[",
        airgap_mode_name(g_airgap.mode), airgap_mode_label(g_airgap.mode),
        g_airgap.open_now ? "true" : "false", esc,
        (long)g_airgap.last_change, (long)g_airgap.next_change,
        g_airgap.time_synced ? "true" : "false",
        g_airgap.require_time_sync ? "true" : "false",
        g_airgap.denied_in, g_airgap.denied_out,
        g_airgap.passed_in, g_airgap.passed_out, g_airgap.blocked_fetches);

    int w_written = 0;
    for (int i = 0; i < g_airgap.window_count && o < cap - 512; i++) {
        ag_window_t *w = &g_airgap.windows[i];
        if (!w->used) continue;
        airgap_days_text(w->days, days, sizeof(days));
        json_escape(w->name, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"name\":\"%s\",\"days\":\"%s\",\"start\":\"%02u:%02u\","
            "\"end\":\"%02u:%02u\",\"in\":%s,\"out\":%s}",
            w_written++ ? "," : "", esc, days,
            w->start_min / 60, w->start_min % 60,
            w->end_min / 60, w->end_min % 60,
            w->allow_in ? "true" : "false", w->allow_out ? "true" : "false");
    }
    pthread_mutex_unlock(&g_airgap.lock);

    /*
     * Per-subsystem refusals. blocked_fetches is the total, but the total
     * alone cannot answer the question an operator actually has while the
     * gap is shut -- "what is still trying?" -- and a breakdown that is
     * all zeros is the quickest way to notice that nothing is being gated
     * at all, which is how this went unnoticed once already.
     */
    o += (size_t)snprintf(b + o, cap - o, "],\"egress\":[");
    for (int k = 0; k < EGRESS_KIND_MAX; k++)
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"subsystem\":\"%s\",\"refused\":%lu}",
            k ? "," : "", egress_kind_name((egress_kind_t)k),
            egress_refusals((egress_kind_t)k));

    o += (size_t)snprintf(b + o, cap - o, "],\"events\":[");
    for (int i = 0; i < n && o < cap - 512; i++) {
        json_escape(ev[i].reason, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"when\":%ld,\"mode\":\"%s\",\"opened\":%s,\"reason\":\"%s\"}",
            i ? "," : "", (long)ev[i].when, airgap_mode_name(ev[i].mode),
            ev[i].opened ? "true" : "false", esc);
    }
    o += (size_t)snprintf(b + o, cap - o, "]}");
    send_json(fd, "200 OK", b);
    free(b);
}

static void api_airgap_mode(int fd, const fx_session_t *s,
                            const char *body, size_t len) {
    char mode[32] = "";
    json_str(body, len, "mode", mode, sizeof(mode));

    ag_mode_t m;
    if (!airgap_mode_from_name(mode, &m)) {
        send_err(fd, "400 Bad Request",
                 "mode must be connected, scheduled, inbound-only, "
                 "outbound-only, isolated or manual");
        return;
    }

    ag_mode_t was = airgap_mode_now(&g_airgap);
    airgap_set_mode(&g_airgap, m, s ? s->user : "console");
    g_netconf.airgap.mode = m;

    /*
     * Recorded whatever the direction. Isolating an appliance and
     * un-isolating it are both worth a line somebody can find afterwards;
     * the second one more than the first, because that is the one that
     * puts the appliance back on the network.
     */
    audited(AUDIT_OK, "airgap.mode", airgap_mode_name(m),
            "boundary changed from %s to %s", airgap_mode_name(was),
            airgap_mode_name(m));
    fprintf(stderr, "[%s] air gap: mode set to %s by %s\n",
            BRAND_PRODUCT, airgap_mode_name(m), s ? s->user : "?");

    mark_unsaved();

    /*
     * The hint is not a nicety on this endpoint. An operator who isolates
     * an appliance and does not save has an appliance that rejoins the
     * network at the next restart -- the failure mode is "the air gap
     * quietly came back open", which is the worst direction for it to
     * fail in.
     */
    char out[320];
    snprintf(out, sizeof(out),
             "{\"ok\":true,\"mode\":\"%s\",\"open\":%s,\"persisted\":false,"
             "\"hint\":\"in effect now; POST /api/config/save or this "
             "appliance returns to '%s' when it restarts\"}",
             airgap_mode_name(m), g_airgap.open_now ? "true" : "false",
             airgap_mode_name(g_netconf_saved_airgap_mode()));
    send_json(fd, "200 OK", out);
}


/* ---- GET /api/audit : the administrative trail ----
 *
 * Admin only. The trail names accounts and source addresses, and a
 * read-only account that can read it learns which operators exist, when
 * they work, and from where -- which is reconnaissance, not oversight.
 */
static void api_audit(int fd, const fx_session_t *s) {
    if (!s || s->role != ROLE_ADMIN) {
        send_err(fd, "403 Forbidden",
                 "the audit trail is visible to administrators only");
        return;
    }

    audit_entry_t ev[AUDIT_RING];
    int n = audit_recent(&g_audit, ev, AUDIT_RING);

    size_t cap = 256 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }

    char esc[512], ip[INET_ADDRSTRLEN];
    size_t o = 0;

    char fpath[320];
    json_escape(g_audit.path, fpath, sizeof(fpath));
    o += (size_t)snprintf(b + o, cap - o,
        "{\"path\":\"%s\",\"records\":%llu,\"write_errors\":%lu,"
        "\"persistent\":%s,\"events\":[",
        fpath, (unsigned long long)g_audit.seq, g_audit.write_errors,
        g_audit.fd >= 0 ? "true" : "false");

    for (int i = 0; i < n && o < cap - 1024; i++) {
        if (ev[i].peer) {
            struct in_addr a = { .s_addr = ev[i].peer };
            inet_ntop(AF_INET, &a, ip, sizeof(ip));
        } else {
            snprintf(ip, sizeof(ip), "-");
        }
        o += (size_t)snprintf(b + o, cap - o, "%s{\"seq\":%llu,\"when\":%ld,",
                              i ? "," : "", (unsigned long long)ev[i].seq,
                              (long)ev[i].when);
        json_escape(ev[i].actor, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o, "\"actor\":\"%s\",", esc);
        json_escape(ev[i].action, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o, "\"action\":\"%s\",", esc);
        json_escape(ev[i].target, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o, "\"target\":\"%s\",", esc);
        json_escape(ev[i].detail, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "\"detail\":\"%s\",\"result\":\"%s\",\"from\":\"%s\"}",
            esc, audit_result_name(ev[i].result), ip);
    }
    o += (size_t)snprintf(b + o, cap - o, "]}");
    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b);
}

/* ---- POST /api/audit/verify : recompute the chain ---- */
static void api_audit_verify(int fd) {
    char why[256];
    int bad = audit_verify(g_audit.path, why, sizeof(why));

    char esc[512];
    json_escape(why, esc, sizeof(esc));

    char out[640];
    snprintf(out, sizeof(out), "{\"intact\":%s,\"record\":%d,\"detail\":\"%s\"}",
             bad == 0 ? "true" : "false", bad, esc);

    /*
     * The verification is itself recorded. An operator who checks the
     * trail and an operator who checks it repeatedly at three in the
     * morning are different facts, and only the trail can hold the second
     * one.
     */
    audited(bad == 0 ? AUDIT_OK : AUDIT_FAILED, "audit.verify", g_audit.path,
            "%s", why);
    send_json(fd, "200 OK", out);
}

static void api_threat(int fd) {
    size_t cap = 512 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t o = 0;
    char esc[512], a[INET_ADDRSTRLEN];

    pthread_mutex_lock(&g_ids.lock);
    o += (size_t)snprintf(b + o, cap - o,
        "{\"enabled\":%s,\"inline\":%s,\"signatures\":%d,"
        "\"states\":%d,\"scanned\":%lu,\"matched\":%lu,\"dropped\":%lu,"
        "\"top\":[",
        g_ids.enabled ? "true" : "false",
        g_ids.inline_mode ? "true" : "false",
        g_ids.sig_count, g_ids.exact.count + g_ids.folded.count,
        g_ids.scanned, g_ids.matched, g_ids.dropped);

    /* The signatures that actually fire, worst first -- a rule table is only
     * interesting where it is hitting. */
    int order[32];
    int n = 0;
    for (int i = 0; i < g_ids.sig_count && n < 32; i++)
        if (g_ids.sigs[i].hits) order[n++] = i;
    for (int i = 1; i < n; i++) {
        int k = order[i], j = i - 1;
        while (j >= 0 && g_ids.sigs[order[j]].hits < g_ids.sigs[k].hits) {
            order[j+1] = order[j]; j--;
        }
        order[j+1] = k;
    }
    for (int i = 0; i < n && o < cap - 512; i++) {
        ids_sig_t *sig = &g_ids.sigs[order[i]];
        json_escape(sig->msg, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"sid\":%d,\"msg\":\"%s\",\"class\":\"%s\","
            "\"action\":\"%s\",\"severity\":%d,\"hits\":%lu,"
            "\"last_hit\":%ld}",
            i ? "," : "", sig->sid, esc, sig_class_name(sig->cls),
            sig_action_name(sig->action), sig->severity, sig->hits,
            (long)sig->last_hit);
    }
    pthread_mutex_unlock(&g_ids.lock);

    o += (size_t)snprintf(b + o, cap - o, "],\"feeds\":[");
    pthread_mutex_lock(&g_feeds.lock);
    for (int i = 0; i < g_feeds.feed_count && o < cap - 512; i++) {
        feed_t *fd2 = &g_feeds.feeds[i];
        json_escape(fd2->last_error, esc, sizeof(esc));
        char urlesc[FEED_URL_LEN * 2];
        json_escape(fd2->url, urlesc, sizeof(urlesc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"name\":\"%s\",\"kind\":\"%s\",\"url\":\"%s\","
            "\"enabled\":%s,\"entries\":%d,\"refresh\":%d,"
            "\"last_fetch\":%ld,\"error\":\"%s\"}",
            i ? "," : "", fd2->name, feed_kind_name(fd2->kind), urlesc,
            fd2->enabled ? "true" : "false", fd2->entries,
            fd2->refresh_minutes, (long)fd2->last_fetch, esc);
    }
    int ranges = g_feeds.range_count, domains = g_feeds.domain_count;
    unsigned long lookups = g_feeds.lookups, iph = g_feeds.ip_hits,
                  dh = g_feeds.domain_hits;
    pthread_mutex_unlock(&g_feeds.lock);

    o += (size_t)snprintf(b + o, cap - o,
        "],\"blocklist\":{\"ranges\":%d,\"domains\":%d,\"lookups\":%lu,"
        "\"ip_hits\":%lu,\"domain_hits\":%lu},\"response\":{",
        ranges, domains, lookups, iph, dh);

    offender_t *off = calloc(256, sizeof(*off));
    int no = off ? response_snapshot(&g_response, off, 256) : 0;

    o += (size_t)snprintf(b + o, cap - o,
        "\"enabled\":%s,\"quarantine\":%s,\"threshold\":%d,"
        "\"blocks\":%lu,\"releases\":%lu,\"escalations\":%lu,"
        "\"offenders\":[",
        g_response.cfg.enabled ? "true" : "false",
        g_response.cfg.quarantine ? "true" : "false",
        g_response.cfg.threshold, g_response.blocks, g_response.releases,
        g_response.escalations);

    time_t now = time(NULL);
    for (int i = 0; i < no && o < cap - 512; i++) {
        json_escape(off[i].last_reason, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, cap - o,
            "%s{\"ip\":\"%s\",\"score\":%d,\"detections\":%d,"
            "\"blocked\":%s,\"remaining\":%ld,\"block_count\":%d,"
            "\"first_seen\":%ld,\"last_seen\":%ld,\"reason\":\"%s\"}",
            i ? "," : "", fx_ip_str(off[i].ip, a, sizeof(a)),
            off[i].score, off[i].detections,
            (off[i].blocked_until > now) ? "true" : "false",
            (off[i].blocked_until > now) ? (long)(off[i].blocked_until - now) : 0L,
            off[i].block_count, (long)off[i].first_seen,
            (long)off[i].last_seen, esc);
    }
    free(off);
    o += (size_t)snprintf(b + o, cap - o, "]}}");

    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b);
}

/* ---- DELETE /api/threat/offenders/<ip> : let a host back in ---- */
static void api_threat_release(int fd, const char *ipstr) {
    struct in_addr ia;
    if (inet_pton(AF_INET, ipstr, &ia) != 1) {
        send_err(fd, "400 Bad Request", "not an IPv4 address");
        return;
    }
    if (response_release(&g_response, ia.s_addr) != 0) {
        send_err(fd, "404 Not Found", "that host has no record");
        return;
    }
    printf("[%s] response: %s released by an operator\n", BRAND_PRODUCT, ipstr);
    send_json(fd, "200 OK", "{\"status\":\"released\"}");
}

/* ---- POST /api/threat/feeds/refresh ---- */
static void api_threat_refresh(int fd) {
    int n = feeds_refresh_due(&g_feeds, time(NULL) + 86400);  /* force all */
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"status\":\"refreshed\",\"feeds\":%d}", n);
    send_json(fd, "200 OK", buf);
}

/* ═══════════════════════ high availability ═══════════════════════ */

/* Defined with the configuration endpoints below; the HA push shares it. */
static int install_config(const char *body, size_t len, const char *who,
                          const char *note, int *warnings,
                          const char **status, char *why, size_t whylen);


/* ---- GET /api/ha ---- */
static void api_ha(int fd) {
    ha_state_t st = ha_read_state(&g_ha);

    pthread_mutex_lock(&g_ha.lock);
    ha_ctx_t h = g_ha;
    pthread_mutex_unlock(&g_ha.lock);

    char esc[384], buf[1024];
    json_escape(h.last_error, esc, sizeof(esc));
    snprintf(buf, sizeof(buf),
        "{\"enabled\":%s,\"role\":\"%s\",\"state\":\"%s\","
        "\"state_since\":%ld,\"transitions\":%lu,\"applied\":%s,"
        "\"vips\":%d,\"peer\":\"%s\",\"sync_interface\":\"%s\","
        "\"vrrp_id\":%d,\"priority\":%d,\"preempt\":%s,"
        "\"conntrack_sync\":%s,\"config_sync\":%s,"
        "\"pushes\":{\"sent\":%lu,\"received\":%lu,\"rejected\":%lu},"
        "\"error\":\"%s\"}",
        h.cfg.enabled ? "true" : "false", ha_role_name(h.cfg.role),
        ha_state_name(st), (long)h.state_since, h.transitions,
        h.applied ? "true" : "false", h.vips,
        h.cfg.peer_address, h.cfg.sync_interface,
        h.cfg.vrrp_id, h.cfg.priority,
        h.cfg.preempt ? "true" : "false",
        h.cfg.conntrack_sync ? "true" : "false",
        h.cfg.config_sync ? "true" : "false",
        h.pushes_sent, h.pushes_received, h.pushes_rejected, esc);
    send_json(fd, "200 OK", buf);
}

/* ---- POST /api/ha/push : send this node's config to the peer ---- */
static void api_ha_push(int fd, const fx_session_t *s) {
    char why[192] = "";
    if (ha_push_config(&g_ha, g_config_path, why, sizeof(why)) != 0) {
        send_err(fd, "502 Bad Gateway", why[0] ? why : "the push failed");
        return;
    }
    printf("[%s] HA: push requested by %s\n", BRAND_PRODUCT, s->user);
    send_json(fd, "200 OK", "{\"status\":\"pushed\"}");
}

/*
 * ---- POST /api/ha/sync : receive a configuration from the peer ----
 *
 * Deliberately not behind a console session. The peer is a machine, not a
 * person, and giving it a user account would mean a credential that works
 * for everything else too. The HMAC proves both that the sender holds the
 * shared secret and that the body arrived unaltered.
 */
static int api_ha_sync(int fd, uint32_t peer_ip, const char *headers,
                       const char *body, size_t len) {
    char ts[32] = "", sig[HA_SIG_LEN] = "", abuf[INET_ADDRSTRLEN];

    if (!g_ha.cfg.enabled || !g_ha.cfg.config_sync) {
        send_err(fd, "403 Forbidden", "configuration sync is not enabled here");
        return 1;
    }

    /* The push must come from the configured peer, not merely be signed. */
    struct in_addr expect;
    if (inet_pton(AF_INET, g_ha.cfg.peer_address, &expect) == 1 &&
        expect.s_addr != peer_ip) {
        pthread_mutex_lock(&g_ha.lock);
        g_ha.pushes_rejected++;
        pthread_mutex_unlock(&g_ha.lock);
        printf("[%s] HA: refused a push from %s; the peer is %s\n",
               BRAND_PRODUCT, fx_ip_str(peer_ip, abuf, sizeof(abuf)),
               g_ha.cfg.peer_address);
        send_err(fd, "403 Forbidden", "not from the configured peer");
        return 1;
    }

    header_get(headers, "X-FireX-HA-Timestamp", ts, sizeof(ts));
    header_get(headers, "X-FireX-HA-Signature", sig, sizeof(sig));

    char why[256];
    if (!ha_verify(g_ha.cfg.sync_secret, ts, sig, body, len, time(NULL),
                   why, sizeof(why))) {
        pthread_mutex_lock(&g_ha.lock);
        g_ha.pushes_rejected++;
        pthread_mutex_unlock(&g_ha.lock);
        printf("[%s] HA: rejected a push from %s: %s\n", BRAND_PRODUCT,
               fx_ip_str(peer_ip, abuf, sizeof(abuf)), why);
        send_err(fd, "401 Unauthorized", why);
        return 1;
    }

    const char *status;
    char err[CFG_ERR_LEN];
    int warnings = 0;
    int rev = install_config(body, len, "ha-peer",
                             "replicated from the primary",
                             &warnings, &status, err, sizeof(err));
    if (rev < 0) {
        pthread_mutex_lock(&g_ha.lock);
        g_ha.pushes_rejected++;
        pthread_mutex_unlock(&g_ha.lock);
        send_err(fd, status, err);
        return 1;
    }

    pthread_mutex_lock(&g_ha.lock);
    g_ha.pushes_received++;
    pthread_mutex_unlock(&g_ha.lock);

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"applied\",\"revision\":%d,\"warnings\":%d}",
             rev, warnings);
    send_json(fd, "200 OK", buf);
    printf("[%s] HA: configuration replicated from the peer (revision %d)\n",
           BRAND_PRODUCT, rev);
    return 1;
}

/* ═══════════════════════ auth endpoints ═══════════════════════ */

/*
 * The cookie attributes, in one place.
 *
 * `Secure` is conditional on TLS actually being terminated, and that is
 * not caution for its own sake: a Secure cookie sent over plain HTTP is
 * discarded by the browser, so hard-coding it would make every login on a
 * cleartext console silently fail with no error anywhere to explain it.
 * Hard-coding it off is the other failure -- the session token then
 * travels to any http:// URL the browser can be pointed at.
 */
static const char *cookie_attrs(void) {
    return blockpage_tls_active(&g_blockpage)
         ? "HttpOnly; Secure; SameSite=Strict; Path=/"
         : "HttpOnly; SameSite=Strict; Path=/";
}

/* The same attributes on the clearing cookie. A browser matches a
 * replacement by name, path and domain, but a Secure attribute that
 * disagrees with the original is one more way for a sign-out to leave the
 * token sitting in the browser after the server has already revoked it. */
static const char *cookie_clear(void) {
    static __thread char buf[160];
    snprintf(buf, sizeof(buf),
             "Set-Cookie: firex_session=; %s; Max-Age=0\r\n", cookie_attrs());
    return buf;
}

static void api_login(int fd, const char *body, size_t len, uint32_t peer) {
    if (!g_ready) {
        send_err(fd, "503 Service Unavailable", "no user database");
        return;
    }

    char user[AUTH_USER_LEN], pass[256];
    if (!json_str(body, len, "username", user, sizeof(user)) ||
        !json_str(body, len, "password", pass, sizeof(pass))) {
        send_err(fd, "400 Bad Request", "username and password are required");
        return;
    }

    fx_session_t s;
    int rc = auth_login(&g_auth, user, pass, peer, &s);
    explicit_bzero(pass, sizeof(pass));

    /*
     * The trail distinguishes these three; the RESPONSE does not. Telling
     * the client apart a throttled account from a wrong password would
     * let it enumerate users, so the detail an investigator needs goes in
     * the audit record, where the client cannot read it.
     *
     * The password is never recorded, in any branch, not even its length.
     */
    if (rc == -2) {
        audit_record(&g_audit, user, peer, AUDIT_DENIED, "auth.login", user,
                     "refused: too many recent failures from this address");
        send_err(fd, "429 Too Many Requests",
                 "too many failed attempts; try again shortly");
        return;
    }
    if (rc == -3) {
        audit_record(&g_audit, user, peer, AUDIT_FAILED, "auth.login", user,
                     "refused: the session table is full");
        send_err(fd, "503 Service Unavailable", "session table full");
        return;
    }
    if (rc != 0) {
        audit_record(&g_audit, user, peer, AUDIT_DENIED, "auth.login", user,
                     "refused: unknown account or wrong password");
        /* Deliberately identical whether the account or the password was
         * wrong, so the response cannot be used to enumerate users. */
        send_err(fd, "401 Unauthorized", "invalid credentials");
        return;
    }

    audit_record(&g_audit, s.user, peer, AUDIT_OK, "auth.login", s.user,
                 "signed in as %s", auth_role_name(s.role));

    char cookie[320];
    snprintf(cookie, sizeof(cookie),
             "Set-Cookie: firex_session=%s; %s; Max-Age=%d\r\n"
             "%s",
             s.token, cookie_attrs(), AUTH_ABSOLUTE_SECONDS,
             /*
              * HSTS only when there is TLS to insist on. Sent from a
              * cleartext console it would pin the browser to an https://
              * origin that does not answer, and the only way back would be
              * to clear the browser's HSTS store -- locking the operator
              * out of the appliance from the appliance's own response.
              */
             blockpage_tls_active(&g_blockpage)
                 ? "Strict-Transport-Security: max-age=31536000\r\n" : "");

    char body_out[256];
    snprintf(body_out, sizeof(body_out),
             "{\"user\":\"%s\",\"role\":\"%s\",\"csrf\":\"%s\"}",
             s.user, auth_role_name(s.role), s.csrf);

    blockpage_send_ex(fd, "200 OK", "application/json", cookie,
                      body_out, strlen(body_out));
}

static void api_logout(int fd, const char *headers, uint32_t peer) {
    char token[AUTH_TOKEN_LEN];
    if (cookie_get(headers, "firex_session", token, sizeof(token))) {
        /* Resolved BEFORE the logout, because afterwards there is no
         * session left to name and the record would read "-". */
        fx_session_t s;
        bool known = auth_session(&g_auth, token, &s);
        auth_logout(&g_auth, token);
        if (known)
            audit_record(&g_audit, s.user, peer, AUDIT_OK, "auth.logout",
                         s.user, "signed out");
    }

    blockpage_send_ex(fd, "200 OK", "application/json",
                      cookie_clear(),
                      "{\"status\":\"signed out\"}", 24);
}

static void api_whoami(int fd, const fx_session_t *s) {
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"user\":\"%s\",\"role\":\"%s\",\"csrf\":\"%s\"}",
             s->user, auth_role_name(s->role), s->csrf);
    send_json(fd, "200 OK", buf);
}

static void api_password(int fd, const fx_session_t *s,
                         const char *body, size_t len) {
    char pass[256];
    if (!json_str(body, len, "password", pass, sizeof(pass))) {
        send_err(fd, "400 Bad Request", "password is required");
        return;
    }
    if (!strcmp(pass, s->user)) {
        explicit_bzero(pass, sizeof(pass));
        send_err(fd, "400 Bad Request",
                 "that is the shipped default; choose something else");
        return;
    }
    if (strlen(pass) < AUTH_MIN_PASSWORD) {
        explicit_bzero(pass, sizeof(pass));
        send_err(fd, "400 Bad Request",
                 "password must be at least 8 characters");
        return;
    }

    int rc = auth_set_password(&g_auth, s->user, pass);
    explicit_bzero(pass, sizeof(pass));

    if (rc != 0) {
        audited(AUDIT_FAILED, "account.password", s->user,
                "the new password could not be stored");
        send_err(fd, "500 Internal Server Error", "could not store the new password");
        return;
    }
    audited(AUDIT_OK, "account.password", s->user,
            "changed their own console password");
    /* Every session for this user was just dropped, including this one. */
    blockpage_send_ex(fd, "200 OK", "application/json",
                      cookie_clear(),
                      "{\"status\":\"password changed; sign in again\"}", 44);
}

/* ═══════════════════════ accounts ═══════════════════════ */

/*
 * Two account databases sit behind one appliance and operators conflate
 * them constantly, so the console reports both in one place:
 *
 *   console  the FireX user file -- the web UI and the serial menu
 *   system   the Linux account   -- SSH and the shell behind the menu
 *
 * Both ship with the user's own name as the password (root/root,
 * admin/admin) so a fresh appliance is always reachable. Neither hash is
 * ever sent to the browser; "default" is the only verdict that leaves
 * this file.
 */

static const char *sys_state_name(int st) {
    switch (st) {
        case 0:  return "set";
        case 1:  return "default";
        case 2:  return "locked";
        case -2: return "unknown";
        default: return "absent";
    }
}

static void api_accounts(int fd, const fx_session_t *s) {
    auth_entry_t users[AUTH_MAX_USERS];
    int n = auth_list(&g_auth, users, AUTH_MAX_USERS);

    char b[4096];
    size_t o = 0;
    int defaults = 0;

    /*
     * Which accounts are still on their shipped password is the single
     * most useful fact on this page -- and the single most useful fact
     * to an attacker who has got as far as a read-only session. A viewer
     * is authenticated, not trusted: the role exists so that somebody can
     * be shown the state of the network without being handed the keys to
     * it.
     *
     * So a viewer sees that the accounts exist and what role each holds,
     * and gets "redacted" where an admin sees "default" or "set". The
     * shape of the response does not change, because a field that
     * disappears for some callers is a field every client has to special
     * case.
     */
    const bool reveal = (s && s->role == ROLE_ADMIN);

    o += (size_t)snprintf(b + o, sizeof(b) - o, "{\"accounts\":[");
    for (int i = 0; i < n && o < sizeof(b) - 512; i++) {
        int st = auth_system_state(users[i].name);
        if (users[i].is_default || st == 1) defaults++;

        char esc[AUTH_USER_LEN * 2];
        json_escape(users[i].name, esc, sizeof(esc));
        o += (size_t)snprintf(b + o, sizeof(b) - o,
                 "%s{\"user\":\"%s\",\"role\":\"%s\","
                 "\"console_default\":%s,\"system\":\"%s\"}",
                 i ? "," : "", esc, auth_role_name(users[i].role),
                 reveal ? (users[i].is_default ? "true" : "false") : "null",
                 reveal ? sys_state_name(st) : "redacted");
    }

    /*
     * root usually has no console account, so it would otherwise be
     * missing from a page whose whole job is to show you that root/root
     * is still live. List it whenever the Linux account exists.
     */
    bool listed_root = false;
    for (int i = 0; i < n; i++)
        if (!strcmp(users[i].name, "root")) listed_root = true;

    int root_st = auth_system_state("root");
    if (!listed_root && root_st >= 0 && o < sizeof(b) - 512) {
        if (root_st == 1) defaults++;
        o += (size_t)snprintf(b + o, sizeof(b) - o,
                 "%s{\"user\":\"root\",\"role\":\"-\","
                 "\"console_default\":%s,\"system\":\"%s\"}",
                 n ? "," : "", reveal ? "false" : "null",
                 reveal ? sys_state_name(root_st) : "redacted");
    }

    /* The count goes the same way: "3 accounts are still on the shipped
     * password" is the same disclosure as naming them. */
    if (reveal)
        snprintf(b + o, sizeof(b) - o,
                 "],\"defaults\":%d,\"redacted\":false,"
                 "\"self\":\"%s\",\"min_password\":%d}",
                 defaults, s->user, AUTH_MIN_PASSWORD);
    else
        snprintf(b + o, sizeof(b) - o,
                 "],\"defaults\":null,\"redacted\":true,"
                 "\"self\":\"%s\",\"min_password\":%d}",
                 s->user, AUTH_MIN_PASSWORD);
    send_json(fd, "200 OK", b);
}

/*
 * POST /api/accounts/password -- {"user":...,"scope":"console"|"system",
 * "password":...}. Admin-gated and CSRF-checked by the router, because
 * this is the one endpoint that can hand somebody else the appliance.
 */
static void api_account_password(int fd, const fx_session_t *s,
                                 const char *body, size_t len) {
    char user[AUTH_USER_LEN], scope[16], pass[256];

    if (!json_str(body, len, "user", user, sizeof(user)) || !user[0]) {
        send_err(fd, "400 Bad Request", "user is required");
        return;
    }
    if (!json_str(body, len, "scope", scope, sizeof(scope)))
        snprintf(scope, sizeof(scope), "console");
    if (!json_str(body, len, "password", pass, sizeof(pass))) {
        send_err(fd, "400 Bad Request", "password is required");
        return;
    }
    /*
     * Checked before the length rule: the shipped defaults are shorter
     * than the minimum, so the other order answers "root" with "too
     * short" and never mentions that it is the password already in use.
     * Refusing it is the point of this page -- otherwise somebody can
     * "change" the password, clear the banner, and change nothing.
     */
    if (!strcmp(pass, user)) {
        explicit_bzero(pass, sizeof(pass));
        send_err(fd, "400 Bad Request",
                 "that is the shipped default; choose something else");
        return;
    }
    if (strlen(pass) < AUTH_MIN_PASSWORD) {
        explicit_bzero(pass, sizeof(pass));
        send_err(fd, "400 Bad Request",
                 "the password must be at least 8 characters");
        return;
    }

    int rc;
    if (!strcmp(scope, "system")) {
        rc = auth_system_set_password(user, pass);
    } else if (!strcmp(scope, "console")) {
        rc = auth_set_password(&g_auth, user, pass);
    } else {
        explicit_bzero(pass, sizeof(pass));
        send_err(fd, "400 Bad Request", "scope must be console or system");
        return;
    }

    bool self_console = !strcmp(scope, "console") && !strcmp(user, s->user);
    explicit_bzero(pass, sizeof(pass));

    if (rc != 0) {
        audited(AUDIT_FAILED, "account.password", user,
                "%s password reset refused", scope);
        send_err(fd, "500 Internal Server Error",
                 !strcmp(scope, "system")
                     ? "chpasswd refused the change"
                     : "no such console account, or the file is unwritable");
        return;
    }

    /*
     * One operator resetting another account's password is the action most
     * worth being able to point at afterwards -- it is how an account is
     * taken over from inside, and the person it belongs to has no other way
     * to find out it happened.
     */
    audited(AUDIT_OK, "account.password", user,
            "%s reset the %s password for %s", s->user, scope, user);

    /* Changing your own console password dropped the session you are on. */
    if (self_console) {
        static const char RE[] =
            "{\"status\":\"password changed; sign in again\",\"reauth\":true}";
        blockpage_send_ex(fd, "200 OK", "application/json",
                          cookie_clear(),
                          RE, sizeof(RE) - 1);
        return;
    }
    send_json(fd, "200 OK", "{\"status\":\"password changed\"}");
}

/* ═══════════════════════ config endpoints ═══════════════════════ */


static void api_revisions(int fd) {
    cfg_revision_t revs[CFG_KEEP_DEFAULT];
    int n = cfgstore_list(&g_cfgstore, revs, CFG_KEEP_DEFAULT);

    size_t cap = 16 * 1024;
    char *b = malloc(cap);
    if (!b) { send_err(fd, "500 Internal Server Error", "out of memory"); return; }

    size_t o = 0;
    char esc[CFG_NOTE_LEN * 2];
    o += (size_t)snprintf(b + o, cap - o, "{\"revisions\":[");
    for (int i = 0; i < n && o < cap - 512; i++) {
        json_escape(revs[i].note, esc, sizeof(esc));
        char author[AUTH_USER_LEN * 2];
        json_escape(revs[i].author, author, sizeof(author));
        o += (size_t)snprintf(b + o, cap - o,
                 "%s{\"revision\":%d,\"time\":%ld,\"author\":\"%s\",\"note\":\"%s\"}",
                 i ? "," : "", revs[i].revision, (long)revs[i].when, author, esc);
    }
    o += (size_t)snprintf(b + o, cap - o, "],\"count\":%d,\"latest\":%d}",
                          n, cfgstore_latest(&g_cfgstore));
    blockpage_send(fd, "200 OK", "application/json", b, o);
    free(b);
}

static void api_save(int fd, const fx_session_t *s, const char *body, size_t len) {
    char note[CFG_NOTE_LEN] = "";
    json_str(body, len, "note", note, sizeof(note));    /* optional */

    /* Never write out a configuration that would not load back. */
    cfg_validate_t res;
    pthread_mutex_lock(&g_vlan.lock);
    pthread_mutex_lock(&g_netconf.lock);
    int bad = firex_validate(&g_vlan, &g_netconf, &g_blockpage, &g_vpn, &res);
    pthread_mutex_unlock(&g_netconf.lock);
    pthread_mutex_unlock(&g_vlan.lock);

    if (bad != 0) { send_err(fd, "409 Conflict", res.error); return; }

    int rev = cfgstore_commit(&g_cfgstore, &g_vlan, &g_netconf, &g_blockpage, &g_policy, &g_vpn,
                              s->user, note[0] ? note : "saved from console");
    if (rev < 0) {
        send_err(fd, "500 Internal Server Error", "could not write the revision");
        return;
    }

    mark_saved();

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"saved\",\"revision\":%d,\"warnings\":%d}",
             rev, res.warnings);
    send_json(fd, "200 OK", buf);
    printf("[%s] config revision %d saved by %s\n", BRAND_PRODUCT, rev, s->user);

    /* Keeping the pair in step is the point of HA; a save that lands on only
     * one node is a failover waiting to surprise someone. */
    if (g_ha.cfg.enabled && g_ha.cfg.config_sync &&
        g_ha.cfg.role == HA_ROLE_PRIMARY) {
        char pwhy[192] = "";
        if (ha_push_config(&g_ha, g_config_path, pwhy, sizeof(pwhy)) != 0)
            fprintf(stderr, "[%s] HA: could not replicate revision %d: %s\n",
                    BRAND_PRODUCT, rev, pwhy);
    }
}

static void api_validate(int fd) {
    cfg_validate_t res;
    int rc = firex_validate_file(g_config_path, &res);

    char err[CFG_ERR_LEN * 2], warn[CFG_ERR_LEN * 2], buf[CFG_ERR_LEN * 5];
    json_escape(res.error,   err,  sizeof(err));
    json_escape(res.warning, warn, sizeof(warn));
    snprintf(buf, sizeof(buf),
             "{\"valid\":%s,\"error\":\"%s\",\"warnings\":%d,\"warning\":\"%s\","
             "\"vlans\":%d,\"ports\":%d,\"acls\":%d,\"wans\":%d,\"forwards\":%d}",
             rc == 0 ? "true" : "false", err, res.warnings, warn,
             res.vlans, res.ports, res.acls, res.wans, res.forwards);
    send_json(fd, rc == 0 ? "200 OK" : "422 Unprocessable Entity", buf);
}

static void api_apply(int fd, const fx_session_t *s) {
    char err[CFG_ERR_LEN];
    printf("[%s] config apply requested by %s\n", BRAND_PRODUCT, s->user);

    if (firex_reload_file(g_config_path, g_apply_net, err, sizeof(err)) != 0) {
        audited(AUDIT_FAILED, "config.apply", g_config_path,
                "rejected: %s", err[0] ? err : "reload failed");
        send_err(fd, "422 Unprocessable Entity",
                 err[0] ? err : "reload failed; previous configuration restored");
        return;
    }
    audited(AUDIT_OK, "config.apply", g_config_path,
            "the running configuration was replaced");
    send_json(fd, "200 OK", "{\"status\":\"applied\"}");
}

static void api_rollback(int fd, const fx_session_t *s,
                         const char *body, size_t len) {
    long rev = 0;
    if (!json_int(body, len, "revision", &rev) || rev <= 0) {
        send_err(fd, "400 Bad Request", "revision is required");
        return;
    }

    char path[CFG_PATH_LEN];
    if (cfgstore_path_for(&g_cfgstore, (int)rev, path, sizeof(path)) != 0) {
        send_err(fd, "404 Not Found", "no such revision");
        return;
    }

    /* Check the old revision still loads before putting it in place: an
     * earlier config can reference interfaces this box no longer has. */
    cfg_validate_t res;
    if (firex_validate_file(path, &res) != 0) {
        send_err(fd, "422 Unprocessable Entity", res.error);
        return;
    }
    if (cfgstore_rollback(&g_cfgstore, (int)rev) != 0) {
        send_err(fd, "500 Internal Server Error", "could not restore that revision");
        return;
    }

    char err[CFG_ERR_LEN];
    if (firex_reload_file(g_config_path, g_apply_net, err, sizeof(err)) != 0) {
        send_err(fd, "422 Unprocessable Entity", err);
        return;
    }

    /* History stays append-only: the rollback itself becomes a new revision. */
    char note[CFG_NOTE_LEN];
    snprintf(note, sizeof(note), "rolled back to revision %ld", rev);
    int newrev = cfgstore_commit(&g_cfgstore, &g_vlan, &g_netconf, &g_blockpage, &g_policy, &g_vpn,
                                 s->user, note);

    audited(AUDIT_OK, "config.rollback", g_config_path,
            "restored revision %ld, recorded as revision %d", rev, newrev);

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"rolled back\",\"from\":%ld,\"revision\":%d}",
             rev, newrev);
    send_json(fd, "200 OK", buf);
    printf("[%s] rolled back to revision %ld by %s\n",
           BRAND_PRODUCT, rev, s->user);
}

static void api_backup(int fd) {
    FILE *f = fopen(g_config_path, "r");
    if (!f) { send_err(fd, "404 Not Found", "no active configuration"); return; }

    size_t cap = 256 * 1024;
    char *b = malloc(cap);
    if (!b) { fclose(f); send_err(fd, "500 Internal Server Error", "out of memory"); return; }
    size_t n = fread(b, 1, cap - 1, f);
    fclose(f);
    b[n] = '\0';

    blockpage_send_ex(fd, "200 OK", "text/plain; charset=utf-8",
                      "Content-Disposition: attachment; "
                      "filename=\"firex.conf\"\r\n", b, n);
    free(b);
}

/*
 * Accepts a whole configuration file as the request body. It is written to a
 * temporary file beside the active one and validated there, so an upload that
 * does not parse never reaches the running appliance.
 */
/*
 * Stages, validates, installs and reloads an uploaded configuration. Shared
 * by the console's restore and the HA push, so both get the same ordering --
 * validate before replacing, and never leave a half-written file where the
 * appliance will boot from it.
 *
 * Returns the new revision on success, or -1 with `why` filled; `status`
 * receives the HTTP status to answer with.
 */
static int install_config(const char *body, size_t len, const char *who,
                          const char *note, int *warnings,
                          const char **status, char *why, size_t whylen) {
    *status = "500 Internal Server Error";
    if (warnings) *warnings = 0;

    if (!len) {
        *status = "400 Bad Request";
        snprintf(why, whylen, "empty upload");
        return -1;
    }

    char tmp[CFG_PATH_LEN + 16];
    if (snprintf(tmp, sizeof(tmp), "%s.restore", g_config_path)
            >= (int)sizeof(tmp)) {
        snprintf(why, whylen, "config path too long");
        return -1;
    }

    FILE *f = fopen(tmp, "w");
    if (!f) {
        snprintf(why, whylen, "cannot stage the upload");
        return -1;
    }
    size_t w = fwrite(body, 1, len, f);
    int bad = (w != len) || (fflush(f) != 0) || (fsync(fileno(f)) != 0);
    if (fclose(f) != 0) bad = 1;
    if (bad) {
        unlink(tmp);
        snprintf(why, whylen, "could not write the upload");
        return -1;
    }

    cfg_validate_t res;
    if (firex_validate_file(tmp, &res) != 0) {
        unlink(tmp);
        *status = "422 Unprocessable Entity";
        snprintf(why, whylen, "%s", res.error);
        return -1;
    }
    if (warnings) *warnings = res.warnings;

    /* Same directory, so this is an atomic replace. */
    if (rename(tmp, g_config_path) != 0) {
        unlink(tmp);
        snprintf(why, whylen, "could not install the upload");
        return -1;
    }

    char err[CFG_ERR_LEN];
    if (firex_reload_file(g_config_path, g_apply_net, err, sizeof(err)) != 0) {
        *status = "422 Unprocessable Entity";
        snprintf(why, whylen, "%s", err);
        return -1;
    }

    int rev = cfgstore_commit(&g_cfgstore, &g_vlan, &g_netconf, &g_blockpage,
                              &g_policy, &g_vpn, who, note);
    *status = "200 OK";
    return rev;
}

static void api_restore(int fd, const fx_session_t *s,
                        const char *body, size_t len) {
    const char *status;
    char why[CFG_ERR_LEN];
    int warnings = 0;

    int rev = install_config(body, len, s->user, "restored from upload",
                             &warnings, &status, why, sizeof(why));
    if (rev < 0) { send_err(fd, status, why); return; }

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"restored\",\"revision\":%d,\"warnings\":%d}",
             rev, warnings);
    send_json(fd, "200 OK", buf);
    printf("[%s] configuration restored from upload by %s (revision %d)\n",
           BRAND_PRODUCT, s->user, rev);
}

/* ═══════════════════════ mutation endpoints ═══════════════════════ */

/*
 * Applies the supplied fields to one VLAN and re-validates the whole
 * configuration before letting the change stand. Both happen under the VLAN
 * lock, so a rejected edit is never observable.
 */
static void api_vlan_put(int fd, uint16_t vid, const char *body, size_t len) {
    char err[CFG_ERR_LEN] = "";
    bool changed = false;

    pthread_mutex_lock(&g_vlan.lock);
    pthread_mutex_lock(&g_netconf.lock);

    vlan_config_t *v = NULL;
    for (int i = 0; i < g_vlan.vlan_count; i++)
        if (g_vlan.vlans[i].vlan_id == vid) { v = &g_vlan.vlans[i]; break; }

    if (!v) {
        pthread_mutex_unlock(&g_netconf.lock);
        pthread_mutex_unlock(&g_vlan.lock);
        send_err(fd, "404 Not Found", "no such VLAN");
        return;
    }

    vlan_config_t before = *v;
    char sbuf[64];
    long num;
    bool flag;

    /* json_str rejects anything that would not fit rather than truncating, so
     * a name read into a VLAN_NAME_LEN buffer always fits the field. */
    char namebuf[VLAN_NAME_LEN];
    if (json_str(body, len, "name", namebuf, sizeof(namebuf))) {
        memcpy(v->name, namebuf, sizeof(namebuf)); changed = true;
    }
    if (json_str(body, len, "description", sbuf, sizeof(sbuf))) {
        snprintf(v->description, VLAN_DESC_LEN, "%s", sbuf); changed = true;
    }
    if (json_str(body, len, "zone", sbuf, sizeof(sbuf))) {
        zone_t z = zone_from(sbuf);
        if (z == ZONE_MAX) {
            snprintf(err, sizeof(err), "unknown zone '%s'", sbuf);
            goto reject;
        }
        v->zone = z; changed = true;
    }

    #define IP_FIELD(key, field) do { \
        if (json_str(body, len, key, sbuf, sizeof(sbuf))) { \
            struct in_addr ia; \
            if (inet_pton(AF_INET, sbuf, &ia) != 1) { \
                snprintf(err, sizeof(err), "%s: '%s' is not an IPv4 address", \
                         key, sbuf); \
                goto reject; \
            } \
            v->field = ia.s_addr; changed = true; \
        } } while (0)

    IP_FIELD("subnet",        subnet);
    IP_FIELD("netmask",       netmask);
    IP_FIELD("gateway",       gateway);
    IP_FIELD("dhcp_start",    dhcp_start);
    IP_FIELD("dhcp_end",      dhcp_end);
    IP_FIELD("dns_primary",   dns_primary);
    IP_FIELD("dns_secondary", dns_secondary);
    #undef IP_FIELD

    #define BOOL_FIELD(key, field) do { \
        if (json_bool(body, len, key, &flag)) { v->field = flag; changed = true; } \
        } while (0)

    BOOL_FIELD("dhcp",             dhcp_enabled);
    BOOL_FIELD("inter_vlan",       inter_vlan_routing);
    BOOL_FIELD("internet",         internet_access);
    BOOL_FIELD("isolation",        client_isolation);
    BOOL_FIELD("dpi",              dpi_enabled);
    BOOL_FIELD("ips",              ips_enabled);
    BOOL_FIELD("malware_scan",     malware_scan);
    BOOL_FIELD("log_all",          log_all);
    BOOL_FIELD("captive_portal",   captive_portal);
    BOOL_FIELD("show_block_page",  show_block_page);
    #undef BOOL_FIELD

    if (json_int(body, len, "lease_time", &num))  { v->lease_time = (int)num; changed = true; }
    if (json_int(body, len, "max_clients", &num)) { v->max_clients = (int)num; changed = true; }
    if (json_int(body, len, "priority", &num)) {
        if (num < 0 || num > 7) {
            snprintf(err, sizeof(err), "priority must be 0-7");
            goto reject;
        }
        v->priority = (uint8_t)num; changed = true;
    }
    if (json_int(body, len, "bandwidth_down_mbps", &num)) {
        v->bandwidth_down_mbps = (int)num; changed = true;
    }
    if (json_int(body, len, "bandwidth_up_mbps", &num)) {
        v->bandwidth_up_mbps = (int)num; changed = true;
    }

    if (!changed) {
        pthread_mutex_unlock(&g_netconf.lock);
        pthread_mutex_unlock(&g_vlan.lock);
        send_err(fd, "400 Bad Request", "no recognised fields in request");
        return;
    }

    cfg_validate_t res;
    if (firex_validate(&g_vlan, &g_netconf, &g_blockpage, &g_vpn, &res) != 0) {
        snprintf(err, sizeof(err), "%s", res.error);
        goto reject;
    }

    pthread_mutex_unlock(&g_netconf.lock);
    pthread_mutex_unlock(&g_vlan.lock);

    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"staged\",\"vlan_id\":%u,\"warnings\":%d,"
             "\"hint\":\"POST /api/config/save then /api/config/apply\"}",
             vid, res.warnings);
    send_json(fd, "200 OK", buf);
    return;

reject:
    *v = before;
    pthread_mutex_unlock(&g_netconf.lock);
    pthread_mutex_unlock(&g_vlan.lock);
    send_err(fd, "422 Unprocessable Entity", err);
}

/* ---- POST /api/aliases ---- */
static void api_alias_create(int fd, const char *body, size_t len) {
    alias_t a;
    memset(&a, 0, sizeof(a));

    char name[POLICY_NAME_LEN], kind[16], entries[2048], desc[POLICY_DESC_LEN];
    if (!json_str(body, len, "name", name, sizeof(name)) || !name[0]) {
        send_err(fd, "400 Bad Request", "name is required");
        return;
    }
    if (!json_str(body, len, "entries", entries, sizeof(entries))) {
        send_err(fd, "400 Bad Request", "entries is required");
        return;
    }
    /* A rule writes the reference as $NAME, so a $ in the name itself would
     * never resolve. */
    for (const char *c = name; *c; c++)
        if (!isalnum((unsigned char)*c) && *c != '_' && *c != '-') {
            send_err(fd, "422 Unprocessable Entity",
                     "alias names may use letters, digits, '_' and '-' only");
            return;
        }

    memcpy(a.name, name, sizeof(name));
    a.kind = json_str(body, len, "kind", kind, sizeof(kind))
           ? policy_alias_kind_from(kind) : ALIAS_NETWORK;
    if (json_str(body, len, "description", desc, sizeof(desc)))
        memcpy(a.description, desc, sizeof(desc));

    if (policy_parse_entries(&a, entries) < 0) {
        send_err(fd, "422 Unprocessable Entity",
                 a.kind == ALIAS_PORT
                   ? "entries must be ports or ranges, e.g. \"80, 443, 8000-8100\""
                   : "entries must be addresses or CIDRs, e.g. \"10.0.0.0/8\"");
        return;
    }

    if (policy_add_alias(&g_policy, &a) != 0) {
        send_err(fd, "409 Conflict", "that alias already exists, or the table is full");
        return;
    }

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"staged\",\"name\":\"%s\",\"entries\":%d}",
             a.name, a.count);
    send_json(fd, "200 OK", buf);
}

/* ---- PUT /api/aliases/<name> ---- */
static void api_alias_put(int fd, const char *name,
                          const char *body, size_t len) {
    alias_t *cur = policy_find_alias(&g_policy, name);
    if (!cur) { send_err(fd, "404 Not Found", "no such alias"); return; }

    alias_t next = *cur;
    char entries[2048], desc[POLICY_DESC_LEN];
    bool changed = false;

    if (json_str(body, len, "entries", entries, sizeof(entries))) {
        if (policy_parse_entries(&next, entries) < 0) {
            send_err(fd, "422 Unprocessable Entity", "entries are malformed");
            return;
        }
        changed = true;
    }
    if (json_str(body, len, "description", desc, sizeof(desc))) {
        memcpy(next.description, desc, sizeof(desc));
        changed = true;
    }
    if (!changed) {
        send_err(fd, "400 Bad Request", "no recognised fields in request");
        return;
    }

    if (policy_update_alias(&g_policy, name, &next) != 0) {
        send_err(fd, "422 Unprocessable Entity", "could not apply the change");
        return;
    }

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"staged\",\"name\":\"%s\",\"entries\":%d}",
             next.name, next.count);
    send_json(fd, "200 OK", buf);
}

/* ---- DELETE /api/aliases/<name> ---- */
static void api_alias_delete(int fd, const char *name) {
    /* Removing an alias a rule still points at would leave that rule matching
     * nothing while still reading as active. Refuse, and say which rule. */
    pthread_mutex_lock(&g_vlan.lock);
    int used_by = -1;
    for (int i = 0; i < g_vlan.ivr_count && used_by < 0; i++) {
        ivr_rule_t *r = &g_vlan.ivr[i];
        if (!strcmp(r->src_alias, name) || !strcmp(r->dst_alias, name) ||
            !strcmp(r->port_alias, name))
            used_by = r->id;
    }
    pthread_mutex_unlock(&g_vlan.lock);

    if (used_by >= 0) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "ACL rule %d still references $%s; change that rule first",
                 used_by, name);
        send_err(fd, "409 Conflict", msg);
        return;
    }

    if (policy_remove_alias(&g_policy, name) != 0) {
        send_err(fd, "404 Not Found", "no such alias");
        return;
    }
    send_json(fd, "200 OK", "{\"status\":\"staged\",\"deleted\":true}");
}

static void api_matrix(int fd, const char *body, size_t len) {
    char fs[32], ts[32], as[32];
    if (!json_str(body, len, "from",   fs, sizeof(fs)) ||
        !json_str(body, len, "to",     ts, sizeof(ts)) ||
        !json_str(body, len, "action", as, sizeof(as))) {
        send_err(fd, "400 Bad Request", "from, to and action are required");
        return;
    }

    zone_t f = zone_from(fs), t = zone_from(ts);
    if (f == ZONE_MAX || t == ZONE_MAX) {
        send_err(fd, "422 Unprocessable Entity", "unknown zone");
        return;
    }
    if (f == t) {
        send_err(fd, "422 Unprocessable Entity",
                 "a zone's policy toward itself is not configurable");
        return;
    }

    vlan_set_zone_policy(&g_vlan, f, t, action_from(as));

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"staged\",\"from\":\"%s\",\"to\":\"%s\",\"action\":\"%s\"}",
             zone_name(f), zone_name(t), action_json(action_from(as)));
    send_json(fd, "200 OK", buf);
}

/* ═══════════════════════ router ═══════════════════════ */

static int webui_route_write(int fd, const char *method, const char *path,
                             uint32_t peer_ip, const char *headers,
                             const char *body, size_t body_len,
                             fx_session_t *sp);

static int webui_route(int fd, const char *method, const char *path,
                       uint32_t peer_ip, const char *headers,
                       const char *body, size_t body_len) {
    fx_session_t s;

    /* The portal answers before anything else: a client being intercepted
     * has no session here and must not be asked for one. */
    if (portal_route(fd, method, path, peer_ip, body, body_len)) return 1;

    /* The HA peer authenticates by signature, not by session. */
    if (!strcmp(path, "/api/ha/sync")) {
        if (strcmp(method, "POST")) {
            send_err(fd, "405 Method Not Allowed", "POST only");
            return 1;
        }
        return api_ha_sync(fd, peer_ip, headers, body, body_len);
    }

    /* ---- static assets, always public: the login form lives here ---- */
    if (!strcmp(method, "GET")) {
        if (!strcmp(path, "/ui") || !strcmp(path, "/ui/")) {
            blockpage_send(fd, "200 OK", "text/html; charset=utf-8",
                           WEBUI_INDEX_HTML, strlen(WEBUI_INDEX_HTML));
            return 1;
        }
        if (!strcmp(path, "/ui/vlan.js")) {
            blockpage_send(fd, "200 OK", "application/javascript",
                           WEBUI_VLAN_JS, strlen(WEBUI_VLAN_JS));
            return 1;
        }
        if (!strcmp(path, "/ui/style.css")) {
            blockpage_send(fd, "200 OK", "text/css",
                           WEBUI_STYLE_CSS, strlen(WEBUI_STYLE_CSS));
            return 1;
        }
    }

    if (strncmp(path, "/api/", 5) != 0)
        return 0;                       /* fall through to the block page */

    /* ---- public API ---- */
    if (!strcmp(path, "/api/auth/login")) {
        if (strcmp(method, "POST")) {
            send_err(fd, "405 Method Not Allowed", "POST only");
            return 1;
        }
        api_login(fd, body, body_len, peer_ip);
        return 1;
    }

    /* ---- everything else needs a session ---- */
    if (!strcmp(path, "/api/auth/logout")) {
        api_logout(fd, headers, peer_ip);  /* idempotent, no gate needed */
        return 1;
    }

    if (!strcmp(method, "GET")) {
        if (!gate(fd, headers, method, false, &s)) return 1;

        if (!strcmp(path, "/api/auth/whoami"))      { api_whoami(fd, &s);  return 1; }
        if (!strcmp(path, "/api/vlans"))            { api_vlans(fd, &s);   return 1; }
        if (!strcmp(path, "/api/blockpage/events")) { api_events(fd);      return 1; }
        if (!strcmp(path, "/api/policy"))           { api_policy(fd);      return 1; }
        if (!strcmp(path, "/api/wan"))              { api_wan(fd);         return 1; }
        if (!strcmp(path, "/api/vpn"))              { api_vpn(fd);         return 1; }
        if (!strcmp(path, "/api/state"))            { api_state(fd);       return 1; }
        if (!strcmp(path, "/api/history"))          { api_history(fd);     return 1; }
        if (!strcmp(path, "/api/telemetry"))        { api_telemetry(fd);   return 1; }
        if (!strcmp(path, "/api/capture"))          { api_capture_status(fd); return 1; }
        if (!strcmp(path, "/api/capture/download")) { api_capture_download(fd); return 1; }
        if (!strcmp(path, "/api/portal"))           { api_portal(fd);      return 1; }
        if (!strcmp(path, "/api/shaping"))          { api_shaping(fd);     return 1; }
        if (!strcmp(path, "/api/ha"))               { api_ha(fd);          return 1; }
        if (!strcmp(path, "/api/threat"))           { api_threat(fd);      return 1; }
        if (!strcmp(path, "/api/system"))           { api_system(fd);      return 1; }
        if (!strcmp(path, "/api/interfaces"))       { api_interfaces(fd);  return 1; }
        if (!strcmp(path, "/api/malware"))          { api_malware(fd);     return 1; }
        if (!strcmp(path, "/api/airgap"))           { api_airgap(fd);      return 1; }
        if (!strcmp(path, "/api/audit"))            { api_audit(fd, &s);   return 1; }
        if (!strcmp(path, "/api/accounts"))         { api_accounts(fd, &s); return 1; }
        if (!strcmp(path, "/api/config/revisions")) { api_revisions(fd);   return 1; }
        if (!strcmp(path, "/api/config/validate"))  { api_validate(fd);    return 1; }
        if (!strcmp(path, "/api/config/backup"))    { api_backup(fd);      return 1; }

        send_err(fd, "404 Not Found", "no such endpoint");
        return 1;
    }

    /* ---- writes: admin role plus a valid CSRF token ---- */
    t_audited = false;
    t_peer    = peer_ip;
    t_actor[0] = 0;
    if (!gate(fd, headers, method, true, &s)) return 1;
    snprintf(t_actor, sizeof(t_actor), "%s", s.user);

    /*
     * Everything below this line changes the appliance, so everything
     * below this line is recorded. The dispatcher's own record is the
     * floor -- method and path, which is enough to answer "what was
     * touched" for the endpoints whose path already says it. Handlers that
     * know more (which mode, which account, which interface) record that
     * instead and set t_audited.
     */
    int handled = webui_route_write(fd, method, path, peer_ip, headers,
                                    body, body_len, &s);
    if (handled) {
        if (!t_audited)
            audit_record(&g_audit, s.user, peer_ip, AUDIT_OK,
                         "config.write", path, "%s", method);
        return 1;
    }
    return 0;
}

/*
 * The write half of the router, split out so the audit record above covers
 * every path through it without a `goto` at each of its twenty returns.
 */
static int webui_route_write(int fd, const char *method, const char *path,
                             uint32_t peer_ip, const char *headers,
                             const char *body, size_t body_len,
                             fx_session_t *sp) {
    fx_session_t s = *sp;
    (void)headers;
    (void)peer_ip;

    if (!strcmp(method, "POST")) {
        if (!strcmp(path, "/api/config/save"))     { api_save(fd, &s, body, body_len);     return 1; }
        if (!strcmp(path, "/api/config/apply"))    { api_apply(fd, &s);                    return 1; }
        if (!strcmp(path, "/api/config/rollback")) { api_rollback(fd, &s, body, body_len); return 1; }
        if (!strcmp(path, "/api/config/restore"))  { api_restore(fd, &s, body, body_len);  return 1; }
        if (!strcmp(path, "/api/zones/matrix"))    { api_matrix(fd, body, body_len);       return 1; }
        if (!strcmp(path, "/api/auth/password"))   { api_password(fd, &s, body, body_len); return 1; }
        if (!strcmp(path, "/api/accounts/password")) { api_account_password(fd, &s, body, body_len); return 1; }
        if (!strcmp(path, "/api/aliases"))         { api_alias_create(fd, body, body_len); return 1; }
        if (!strcmp(path, "/api/vpn/keygen"))      { api_vpn_keygen(fd);                   return 1; }
        if (!strcmp(path, "/api/vpn/peers"))       { api_peer_create(fd, body, body_len);  return 1; }
        if (!strcmp(path, "/api/capture/start"))   { api_capture_start(fd, &s, body, body_len); return 1; }
        if (!strcmp(path, "/api/capture/stop"))    { api_capture_stop(fd);                 return 1; }
        if (!strcmp(path, "/api/portal/vouchers")) { api_portal_vouchers(fd, body, body_len); return 1; }
        if (!strcmp(path, "/api/ha/push"))         { api_ha_push(fd, &s);  return 1; }
        if (!strcmp(path, "/api/threat/feeds/refresh")) { api_threat_refresh(fd); return 1; }
        if (!strcmp(path, "/api/malware/mode"))    { api_malware_mode(fd, &s, body, body_len); return 1; }
        if (!strcmp(path, "/api/malware/reload"))  { api_malware_reload(fd); return 1; }
        if (!strcmp(path, "/api/airgap/mode"))     { api_airgap_mode(fd, &s, body, body_len);  return 1; }
        if (!strcmp(path, "/api/audit/verify"))    { api_audit_verify(fd); return 1; }
    }

    if (!strncmp(path, "/api/interfaces/", 16)) {
        const char *rest = path + 16;
        const char *slash = strchr(rest, '/');
        if (!slash || strcmp(slash, "/admin") != 0) {
            send_err(fd, "404 Not Found", "no such endpoint");
            return 1;
        }
        char name[64];
        size_t n = (size_t)(slash - rest);
        if (n == 0 || n >= sizeof(name)) {
            send_err(fd, "400 Bad Request", "interface name is required");
            return 1;
        }
        memcpy(name, rest, n);
        name[n] = 0;
        if (!strcmp(method, "POST")) { api_interface_admin(fd, name, body, body_len); return 1; }
        send_err(fd, "405 Method Not Allowed", "POST");
        return 1;
    }

    if (!strncmp(path, "/api/threat/offenders/", 22)) {
        const char *who = path + 22;
        if (!*who || strchr(who, '/')) {
            send_err(fd, "400 Bad Request", "an address is required");
            return 1;
        }
        if (!strcmp(method, "DELETE")) { api_threat_release(fd, who); return 1; }
        send_err(fd, "405 Method Not Allowed", "DELETE");
        return 1;
    }

    if (!strncmp(path, "/api/portal/sessions/", 21)) {
        const char *who = path + 21;
        if (!*who || strchr(who, '/')) {
            send_err(fd, "400 Bad Request", "an address is required");
            return 1;
        }
        if (!strcmp(method, "DELETE")) { api_portal_kick(fd, who); return 1; }
        send_err(fd, "405 Method Not Allowed", "DELETE");
        return 1;
    }

    if (!strncmp(path, "/api/vpn/peers/", 15)) {
        const char *name = path + 15;
        if (!*name || strchr(name, '/')) {
            send_err(fd, "400 Bad Request", "peer name is required");
            return 1;
        }
        if (!strcmp(method, "DELETE")) { api_peer_delete(fd, name); return 1; }
        send_err(fd, "405 Method Not Allowed", "DELETE");
        return 1;
    }

    if (!strncmp(path, "/api/aliases/", 13)) {
        const char *name = path + 13;
        if (!*name || strchr(name, '/')) {
            send_err(fd, "400 Bad Request", "alias name is required");
            return 1;
        }
        if (!strcmp(method, "PUT"))    { api_alias_put(fd, name, body, body_len); return 1; }
        if (!strcmp(method, "DELETE")) { api_alias_delete(fd, name);              return 1; }
        send_err(fd, "405 Method Not Allowed", "PUT or DELETE");
        return 1;
    }

    if (!strcmp(method, "PUT") && !strncmp(path, "/api/vlans/", 11)) {
        char *end = NULL;
        long vid = strtol(path + 11, &end, 10);
        if (vid < 1 || vid > 4094 || (end && *end && *end != '?')) {
            send_err(fd, "400 Bad Request", "VLAN id must be 1-4094");
            return 1;
        }
        api_vlan_put(fd, (uint16_t)vid, body, body_len);
        return 1;
    }

    send_err(fd, "404 Not Found", "no such endpoint");
    return 1;
}

/* ═══════════════════════ lifecycle ═══════════════════════ */

int webui_init(const char *users_path, const char *active_config) {
    snprintf(g_config_path, sizeof(g_config_path), "%s", active_config);

    int rc = 0;
    if (auth_init(&g_auth, users_path) != 0) {
        fprintf(stderr, "[%s] console auth unavailable; the console will "
                "refuse every request\n", BRAND_PRODUCT);
        rc = -1;
    }
    if (cfgstore_init(&g_cfgstore, active_config) != 0) {
        fprintf(stderr, "[%s] config history unavailable; save and rollback "
                "will fail\n", BRAND_PRODUCT);
    }
    g_ready = (rc == 0);
    return rc;
}

void webui_set_capture_dir(const char *dir) {
    if (dir && *dir) snprintf(g_capture_dir, sizeof(g_capture_dir), "%s", dir);
}

void webui_set_runtime(const char *active_config, bool apply_net) {
    if (active_config)
        snprintf(g_config_path, sizeof(g_config_path), "%s", active_config);
    g_apply_net = apply_net;
}

void webui_attach(blockpage_ctx_t *bp) {
    blockpage_set_router(bp, webui_route);
    /*
     * No port here. The console's listener is configured after this and
     * announces itself when it binds; naming the block page's port at
     * attach time printed a number the console was never reachable on,
     * which is worse than printing none.
     */
    printf("[%s] Admin console routes registered (%s)\n", BRAND_PRODUCT,
           g_ready ? "authenticated" : "DISABLED - no user database");
}

void webui_shutdown(void) {
    if (g_ready) auth_shutdown(&g_auth);
    cfgstore_shutdown(&g_cfgstore);
    g_ready = false;
}
