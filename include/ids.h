#ifndef FIREX_IDS_H
#define FIREX_IDS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "firewall.h"

/*
 * Signature matching.
 *
 * The naive shape -- loop over every rule and memmem() its pattern -- costs
 * O(rules x payload) per packet, which stops being viable somewhere around a
 * hundred rules. This builds an Aho-Corasick automaton instead: every
 * pattern is matched in a single pass over the payload, so adding the
 * thousandth signature costs the same per packet as the first.
 *
 * Two automatons are built, one for case-sensitive patterns and one for
 * case-insensitive ones, because folding case inside a single automaton
 * means either losing the distinction or doubling every state.
 *
 * What this is NOT: Suricata. There is no stream reassembly, no flow
 * tracking, no PCRE, and no protocol parsers. A signature matches within one
 * packet's payload, so a pattern split across two segments is missed. That
 * limit is real and worth knowing before trusting a rule.
 */

#define IDS_MAX_SIGS       2048
#define IDS_PATTERN_LEN    128
#define IDS_MSG_LEN        160
#define IDS_REF_LEN        96

typedef enum {
    SIG_ALERT = 0,   /* record it and let the packet through */
    SIG_DROP,        /* record it and drop the packet silently */
    SIG_REJECT       /* record it, drop, and serve the block page */
} sig_action_t;

typedef enum {
    SIG_CLASS_MALWARE = 0,
    SIG_CLASS_C2,
    SIG_CLASS_EXPLOIT,
    SIG_CLASS_RECON,
    SIG_CLASS_DOS,
    SIG_CLASS_POLICY,
    SIG_CLASS_MAX
} sig_class_t;

typedef struct {
    int           sid;            /* signature id, unique */
    int           rev;
    sig_action_t  action;
    sig_class_t   cls;
    int           severity;       /* 1 (noise) to 4 (serious) */

    uint8_t       protocol;       /* 0 = any */
    uint16_t      src_port;       /* 0 = any */
    uint16_t      dst_port;       /* 0 = any */

    unsigned char content[IDS_PATTERN_LEN];
    int           content_len;
    bool          nocase;
    int           offset;         /* ignore matches before this byte */
    int           depth;          /* ignore matches past offset+depth; 0 = all */

    char          msg[IDS_MSG_LEN];
    char          reference[IDS_REF_LEN];

    bool          enabled;
    unsigned long hits;
    time_t        last_hit;
} ids_sig_t;

/* ── Aho-Corasick ──
 * Nodes carry a sorted edge array rather than a 256-wide table: most nodes
 * have one or two children, and a flat table per node would cost hundreds of
 * megabytes for a realistic ruleset.
 */
typedef struct {
    int32_t   fail;
    int32_t   sig;        /* index of a signature ending here, or -1 */
    int32_t   out_link;   /* next node holding an output, via fail links */
    uint16_t  nedges;
    uint8_t  *echar;      /* sorted ascending */
    int32_t  *enext;
} ac_node_t;

typedef struct {
    ac_node_t *nodes;
    int        count, cap;
    bool       built;
    int        patterns;
} ac_t;

typedef struct {
    ids_sig_t       sigs[IDS_MAX_SIGS];
    int             sig_count;

    ac_t            exact;        /* case-sensitive patterns   */
    ac_t            folded;       /* case-insensitive patterns */

    bool            enabled;
    bool            inline_mode;  /* false: alert only, never drop */

    unsigned long   scanned, matched, dropped;
    pthread_mutex_t lock;
} ids_ctx_t;

typedef struct {
    int          sid;
    sig_class_t  cls;
    sig_action_t action;
    int          severity;
    const char  *msg;
    int          offset;          /* where in the payload it matched */
} ids_hit_t;

/* The settings that live in the configuration file, as distinct from the
 * compiled ruleset the engine holds. */
typedef struct {
    bool enabled;
    bool inline_mode;        /* false: report, never drop */
    char rules_path[256];
    bool feeds_enabled;
} threat_cfg_t;

int  ids_init(ids_ctx_t *c);
void ids_shutdown(ids_ctx_t *c);

/* Adds one signature. -1 when the sid is taken, the table is full, or the
 * signature has no content to match. */
int  ids_add(ids_ctx_t *c, const ids_sig_t *s);

/*
 * Parses one rule line. The accepted form is a documented subset of the
 * Snort syntax:
 *
 *   alert tcp any any -> any 80 (msg:"..."; content:"GET /admin"; nocase;
 *                                offset:0; depth:64; class:recon;
 *                                sid:1000001; rev:1; severity:2;
 *                                reference:"...";)
 *
 * Content may be text, or hex between pipes: content:"|90 90 90 90|".
 * Returns 0 on success, -1 with `why` filled otherwise.
 */
int  ids_parse_rule(const char *line, ids_sig_t *out, char *why, size_t whylen);

/* Loads a rule file, one rule per line, # for comments. Returns how many
 * were loaded; `bad` receives how many were rejected. */
int  ids_load_file(ids_ctx_t *c, const char *path, int *bad);

/* Compiles the automatons. Must be called after the last ids_add(). */
int  ids_compile(ids_ctx_t *c);

/*
 * Scans one payload. Returns the number of signatures that matched and
 * fills `hits` with up to `max` of them, worst severity first. The verdict
 * is the caller's: `ids_verdict()` turns hits into an action.
 */
int  ids_scan(ids_ctx_t *c, const unsigned char *payload, int len,
              uint8_t proto, uint16_t sport, uint16_t dport,
              ids_hit_t *hits, int max);

/* The action the most serious hit calls for, honouring inline_mode. */
sig_action_t ids_verdict(const ids_ctx_t *c, const ids_hit_t *hits, int n);

const char *sig_class_name(sig_class_t c);
sig_class_t sig_class_from(const char *s);
const char *sig_action_name(sig_action_t a);
sig_action_t sig_action_from(const char *s);

/* ── the automaton, exposed so it can be tested on its own ── */
int  ac_init(ac_t *a);
void ac_free(ac_t *a);
int  ac_add(ac_t *a, const unsigned char *pat, int len, int sig_index);
int  ac_build(ac_t *a);

/*
 * Calls `cb` for every pattern occurrence. `end` is the index of the last
 * byte of the match, so the start is end - patlen + 1.
 */
typedef void (*ac_cb)(int sig_index, int end, void *user);
int  ac_search(const ac_t *a, const unsigned char *text, int len,
               ac_cb cb, void *user);

#endif
