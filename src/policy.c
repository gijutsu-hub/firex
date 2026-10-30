/*
 * Aliases and schedules. See include/policy.h for the contract.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "policy.h"
#include "netutil.h"

static const char *DAYNAME[7] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };

int policy_init(policy_ctx_t *p) {
    memset(p, 0, sizeof(*p));
    pthread_mutex_init(&p->lock, NULL);
    return 0;
}

void policy_shutdown(policy_ctx_t *p) {
    if (!p) return;
    pthread_mutex_destroy(&p->lock);
}

const char *policy_alias_kind_str(alias_kind_t k) {
    return k == ALIAS_PORT ? "port" : "network";
}

alias_kind_t policy_alias_kind_from(const char *s) {
    if (s && (!strcasecmp(s, "port") || !strcasecmp(s, "ports")))
        return ALIAS_PORT;
    return ALIAS_NETWORK;
}

/* ── parsing ───────────────────────────────────────────────────────── */

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

int policy_parse_hhmm(const char *s, int *minutes) {
    if (!s || !*s) return -1;
    int h = -1, m = -1;
    char extra;
    if (sscanf(s, "%d:%d%c", &h, &m, &extra) != 2) return -1;
    if (h < 0 || h > 24 || m < 0 || m > 59) return -1;
    if (h == 24 && m != 0) return -1;        /* 24:00 is midnight, nothing past */
    *minutes = h * 60 + m;
    if (*minutes > 1440) return -1;
    if (*minutes == 1440) *minutes = 0;
    return 0;
}

const char *policy_hhmm_str(int minutes, char *buf, size_t len) {
    if (minutes < 0) minutes = 0;
    snprintf(buf, len, "%02d:%02d", (minutes / 60) % 24, minutes % 60);
    return buf;
}

int policy_parse_days(const char *s, uint8_t *out) {
    if (!s || !*s) return -1;
    *out = 0;

    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s", s);

    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *t = trim(tok);
        if (!*t) continue;

        if (!strcasecmp(t, "daily") || !strcasecmp(t, "all")) { *out = 0x7f; continue; }
        if (!strcasecmp(t, "weekdays")) { *out |= 0x3e;       continue; }  /* Mon-Fri */
        if (!strcasecmp(t, "weekends")) { *out |= 0x41;       continue; }  /* Sun+Sat */

        int found = -1;
        for (int d = 0; d < 7; d++)
            if (!strncasecmp(t, DAYNAME[d], 3) && strlen(t) >= 3) { found = d; break; }
        if (found < 0) return -1;
        *out |= (uint8_t)(1u << found);
    }
    return *out ? 0 : -1;
}

const char *policy_days_str(uint8_t days, char *buf, size_t len) {
    if ((days & 0x7f) == 0x7f) { snprintf(buf, len, "daily"); return buf; }
    if ((days & 0x7f) == 0x3e) { snprintf(buf, len, "weekdays"); return buf; }
    if ((days & 0x7f) == 0x41) { snprintf(buf, len, "weekends"); return buf; }

    size_t o = 0;
    buf[0] = '\0';
    for (int d = 0; d < 7; d++) {
        if (!((days >> d) & 1)) continue;
        int w = snprintf(buf + o, len - o, "%s%s", o ? "," : "", DAYNAME[d]);
        if (w < 0 || (size_t)w >= len - o) break;
        o += (size_t)w;
    }
    if (!o) snprintf(buf, len, "none");
    return buf;
}

/* "80", "8000-8100", "10.0.0.0/8", "192.168.1.5" */
int policy_parse_entries(alias_t *a, const char *csv) {
    if (!a || !csv) return -1;
    a->count = 0;

    char tmp[1024];
    if (snprintf(tmp, sizeof(tmp), "%s", csv) >= (int)sizeof(tmp)) return -1;

    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *t = trim(tok);
        if (!*t) continue;
        if (a->count >= ALIAS_ENTRIES) return -1;

        if (a->kind == ALIAS_PORT) {
            long lo = 0, hi = 0;
            char *dash = strchr(t, '-');
            char *end = NULL;

            if (dash) {
                *dash = '\0';
                lo = strtol(t, &end, 10);
                if (end == t || *end) return -1;
                char *h = trim(dash + 1);
                hi = strtol(h, &end, 10);
                if (end == h || *end) return -1;
            } else {
                lo = hi = strtol(t, &end, 10);
                if (end == t || *end) return -1;
            }
            if (lo < 1 || hi < 1 || lo > 65535 || hi > 65535 || lo > hi) return -1;

            a->ports[a->count].start = (uint16_t)lo;
            a->ports[a->count].end   = (uint16_t)hi;
            a->count++;
        } else {
            uint32_t ip = 0, mask = 0;
            /* A bare address is a host, so fx_parse_cidr's /32 default is
             * exactly right; what it cannot do is tell a typo from "any". */
            if (!strcmp(t, "*") || !strcasecmp(t, "any")) return -1;
            fx_parse_cidr(t, &ip, &mask);
            if (!ip && !mask) return -1;

            a->nets[a->count].ip   = ip;
            a->nets[a->count].mask = mask;
            a->count++;
        }
    }
    return a->count ? a->count : -1;
}

const char *policy_entries_str(const alias_t *a, char *buf, size_t len) {
    size_t o = 0;
    buf[0] = '\0';
    for (int i = 0; i < a->count; i++) {
        char one[64];
        if (a->kind == ALIAS_PORT) {
            if (a->ports[i].start == a->ports[i].end)
                snprintf(one, sizeof(one), "%u", a->ports[i].start);
            else
                snprintf(one, sizeof(one), "%u-%u", a->ports[i].start, a->ports[i].end);
        } else {
            fx_cidr_str(a->nets[i].ip, a->nets[i].mask, one, sizeof(one));
        }
        int w = snprintf(buf + o, len - o, "%s%s", o ? ", " : "", one);
        if (w < 0 || (size_t)w >= len - o) break;
        o += (size_t)w;
    }
    return buf;
}

/* ── tables ────────────────────────────────────────────────────────── */

static alias_t *find_alias_locked(policy_ctx_t *p, const char *name) {
    if (!name || !*name) return NULL;
    /* Rules may write the reference with its $ sigil; accept either form. */
    if (*name == '$') name++;
    for (int i = 0; i < p->alias_count; i++)
        if (!strcmp(p->aliases[i].name, name)) return &p->aliases[i];
    return NULL;
}

static schedule_t *find_sched_locked(policy_ctx_t *p, const char *name) {
    if (!name || !*name) return NULL;
    for (int i = 0; i < p->schedule_count; i++)
        if (!strcmp(p->schedules[i].name, name)) return &p->schedules[i];
    return NULL;
}

int policy_add_alias(policy_ctx_t *p, const alias_t *a) {
    if (!a->name[0] || a->count <= 0) return -1;

    pthread_mutex_lock(&p->lock);
    if (p->alias_count >= MAX_ALIASES || find_alias_locked(p, a->name)) {
        pthread_mutex_unlock(&p->lock);
        return -1;
    }
    p->aliases[p->alias_count] = *a;
    p->aliases[p->alias_count].enabled = true;
    p->aliases[p->alias_count].hits = 0;
    p->alias_count++;
    pthread_mutex_unlock(&p->lock);
    return 0;
}

int policy_add_schedule(policy_ctx_t *p, const schedule_t *s) {
    if (!s->name[0] || !s->days) return -1;

    pthread_mutex_lock(&p->lock);
    if (p->schedule_count >= MAX_SCHEDULES || find_sched_locked(p, s->name)) {
        pthread_mutex_unlock(&p->lock);
        return -1;
    }
    p->schedules[p->schedule_count] = *s;
    p->schedules[p->schedule_count].enabled = true;
    p->schedule_count++;
    pthread_mutex_unlock(&p->lock);
    return 0;
}

int policy_update_alias(policy_ctx_t *p, const char *name, const alias_t *src) {
    if (!src || src->count <= 0) return -1;

    pthread_mutex_lock(&p->lock);
    alias_t *a = find_alias_locked(p, name);
    if (!a || a->kind != src->kind) {
        pthread_mutex_unlock(&p->lock);
        return -1;
    }
    memcpy(a->nets,  src->nets,  sizeof(a->nets));
    memcpy(a->ports, src->ports, sizeof(a->ports));
    a->count = src->count;
    if (src->description[0])
        memcpy(a->description, src->description, sizeof(a->description));
    pthread_mutex_unlock(&p->lock);
    return 0;
}

int policy_remove_alias(policy_ctx_t *p, const char *name) {
    pthread_mutex_lock(&p->lock);
    alias_t *a = find_alias_locked(p, name);
    if (!a) {
        pthread_mutex_unlock(&p->lock);
        return -1;
    }
    int idx = (int)(a - p->aliases);
    for (int i = idx; i < p->alias_count - 1; i++)
        p->aliases[i] = p->aliases[i + 1];
    p->alias_count--;
    memset(&p->aliases[p->alias_count], 0, sizeof(p->aliases[0]));
    pthread_mutex_unlock(&p->lock);
    return 0;
}

alias_t *policy_find_alias(policy_ctx_t *p, const char *name) {
    pthread_mutex_lock(&p->lock);
    alias_t *a = find_alias_locked(p, name);
    pthread_mutex_unlock(&p->lock);
    return a;
}

schedule_t *policy_find_schedule(policy_ctx_t *p, const char *name) {
    pthread_mutex_lock(&p->lock);
    schedule_t *s = find_sched_locked(p, name);
    pthread_mutex_unlock(&p->lock);
    return s;
}

/* ── matching ──────────────────────────────────────────────────────── */

bool policy_match_ip(policy_ctx_t *p, const char *name, uint32_t ip) {
    if (!p) return false;

    pthread_mutex_lock(&p->lock);
    alias_t *a = find_alias_locked(p, name);
    bool hit = false;
    if (a && a->enabled && a->kind == ALIAS_NETWORK) {
        for (int i = 0; i < a->count; i++)
            if ((ip & a->nets[i].mask) == (a->nets[i].ip & a->nets[i].mask)) {
                hit = true;
                break;
            }
        if (hit) a->hits++;
    }
    pthread_mutex_unlock(&p->lock);
    return hit;
}

bool policy_match_port(policy_ctx_t *p, const char *name, uint16_t port) {
    if (!p) return false;

    pthread_mutex_lock(&p->lock);
    alias_t *a = find_alias_locked(p, name);
    bool hit = false;
    if (a && a->enabled && a->kind == ALIAS_PORT) {
        for (int i = 0; i < a->count; i++)
            if (port >= a->ports[i].start && port <= a->ports[i].end) {
                hit = true;
                break;
            }
        if (hit) a->hits++;
    }
    pthread_mutex_unlock(&p->lock);
    return hit;
}

bool policy_window_active(const schedule_t *s, time_t now) {
    if (!s || !s->enabled || !s->days) return false;

    struct tm tmv;
    localtime_r(&now, &tmv);
    int min  = tmv.tm_hour * 60 + tmv.tm_min;
    int wday = tmv.tm_wday;                       /* 0 = Sunday */

    const uint8_t today = (uint8_t)(1u << wday);

    if (s->start_min == s->end_min)               /* all day on its days */
        return (s->days & today) != 0;

    if (s->start_min < s->end_min)
        return (s->days & today) && min >= s->start_min && min < s->end_min;

    /*
     * The window crosses midnight. The hours after midnight belong to the
     * window that opened the previous evening, so a "weekdays 22:00-06:00"
     * schedule covers Saturday 02:00 (opened Friday) but not Monday 02:00.
     */
    if (min >= s->start_min) return (s->days & today) != 0;
    if (min <  s->end_min) {
        uint8_t yesterday = (uint8_t)(1u << ((wday + 6) % 7));
        return (s->days & yesterday) != 0;
    }
    return false;
}

bool policy_schedule_active(policy_ctx_t *p, const char *name, time_t now) {
    if (!p || !name || !*name) return false;

    pthread_mutex_lock(&p->lock);
    schedule_t *s = find_sched_locked(p, name);
    bool active = s ? policy_window_active(s, now) : false;
    pthread_mutex_unlock(&p->lock);
    return active;
}
