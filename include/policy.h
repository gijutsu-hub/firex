#ifndef FIREX_POLICY_H
#define FIREX_POLICY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

/*
 * Aliases and schedules: the two things that make a rule table survive
 * growth.
 *
 * An alias is a named set of networks or ports that rules reference as
 * $NAME, so "the server pool" is written down once and every rule that
 * mentions it follows when it changes. A schedule is a named recurring time
 * window; a rule carrying one is skipped outside it.
 *
 * Both are resolved at match time rather than expanded into the rule table,
 * so editing an alias takes effect without regenerating any rules.
 */

#define MAX_ALIASES        64
#define MAX_SCHEDULES      32
#define ALIAS_ENTRIES      64
#define POLICY_NAME_LEN    32
#define POLICY_DESC_LEN    96

typedef enum {
    ALIAS_NETWORK,   /* hosts and networks; a host is simply a /32 */
    ALIAS_PORT
} alias_kind_t;

typedef struct { uint32_t ip, mask; } alias_net_t;
typedef struct { uint16_t start, end; } alias_port_t;

typedef struct {
    char         name[POLICY_NAME_LEN];
    char         description[POLICY_DESC_LEN];
    alias_kind_t kind;
    int          count;
    alias_net_t  nets[ALIAS_ENTRIES];
    alias_port_t ports[ALIAS_ENTRIES];
    bool         enabled;
    unsigned long hits;
} alias_t;

typedef struct {
    char    name[POLICY_NAME_LEN];
    char    description[POLICY_DESC_LEN];
    uint8_t days;        /* bit 0 = Sunday ... bit 6 = Saturday */
    int     start_min;   /* minutes since midnight */
    int     end_min;     /* <= start_min means the window crosses midnight */
    bool    enabled;
} schedule_t;

typedef struct policy_ctx {
    alias_t    aliases[MAX_ALIASES];
    int        alias_count;

    schedule_t schedules[MAX_SCHEDULES];
    int        schedule_count;

    /*
     * Held for the duration of any lookup. vlan_check_forward() calls into
     * here while holding the VLAN lock, so the order is always
     * vlan -> policy; nothing here ever calls back into the VLAN engine.
     */
    pthread_mutex_t lock;
} policy_ctx_t;

int  policy_init(policy_ctx_t *p);
void policy_shutdown(policy_ctx_t *p);

/* -1 when the name is taken, the table is full or the alias is malformed. */
int  policy_add_alias(policy_ctx_t *p, const alias_t *a);
int  policy_add_schedule(policy_ctx_t *p, const schedule_t *s);

/* Return NULL when absent. The caller must hold no policy lock. */
alias_t    *policy_find_alias(policy_ctx_t *p, const char *name);

/* Replaces an existing alias's entries and description in place. -1 when the
 * name is unknown. The kind cannot change: rules reference it by kind, and a
 * silent switch would turn a port rule into an address rule. */
int  policy_update_alias(policy_ctx_t *p, const char *name,
                         const alias_t *src);

/* -1 when the alias is unknown. The caller is expected to have checked that
 * no rule still references it. */
int  policy_remove_alias(policy_ctx_t *p, const char *name);
schedule_t *policy_find_schedule(policy_ctx_t *p, const char *name);

/*
 * Membership tests. An unknown alias name matches nothing: a rule that
 * references a missing alias must not silently widen into match-anything.
 * Validation rejects such references before they can reach a live table.
 */
bool policy_match_ip(policy_ctx_t *p, const char *alias, uint32_t ip);
bool policy_match_port(policy_ctx_t *p, const char *alias, uint16_t port);

/* An unknown or disabled schedule reads as inactive, for the same reason. */
bool policy_schedule_active(policy_ctx_t *p, const char *name, time_t now);

/* Window test on a single schedule, exposed so tests can drive the clock. */
bool policy_window_active(const schedule_t *s, time_t now);

/* ── parsing / formatting, shared by the loader and the serialiser ── */

/* "10.0.0.0/8, 192.168.1.5" or "80, 443, 8000-8100". Returns entries parsed,
 * or -1 if any entry is malformed. */
int  policy_parse_entries(alias_t *a, const char *csv);

/* "mon,tue,wed" or "weekdays" / "weekends" / "daily". -1 on a bad token. */
int  policy_parse_days(const char *s, uint8_t *out);

/* "09:00" -> 540. -1 when malformed. */
int  policy_parse_hhmm(const char *s, int *minutes);

const char *policy_days_str(uint8_t days, char *buf, size_t len);
const char *policy_hhmm_str(int minutes, char *buf, size_t len);
const char *policy_alias_kind_str(alias_kind_t k);
alias_kind_t policy_alias_kind_from(const char *s);

/* Formats an alias's entries back into the comma-separated form above. */
const char *policy_entries_str(const alias_t *a, char *buf, size_t len);

#endif
