/*
 * Signature matching. See include/ids.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>

#include "ids.h"
#include "brand.h"

/* ═══════════════════ Aho-Corasick ═══════════════════ */

#define AC_INITIAL_NODES 256

int ac_init(ac_t *a) {
    memset(a, 0, sizeof(*a));
    a->nodes = calloc(AC_INITIAL_NODES, sizeof(ac_node_t));
    if (!a->nodes) return -1;
    a->cap = AC_INITIAL_NODES;

    /* Node 0 is the root. */
    a->nodes[0].fail     = 0;
    a->nodes[0].sig      = -1;
    a->nodes[0].out_link = -1;
    a->count = 1;
    return 0;
}

void ac_free(ac_t *a) {
    if (!a->nodes) return;
    for (int i = 0; i < a->count; i++) {
        free(a->nodes[i].echar);
        free(a->nodes[i].enext);
    }
    free(a->nodes);
    memset(a, 0, sizeof(*a));
}

static int ac_new_node(ac_t *a) {
    if (a->count >= a->cap) {
        int ncap = a->cap * 2;
        ac_node_t *n = realloc(a->nodes, (size_t)ncap * sizeof(ac_node_t));
        if (!n) return -1;
        memset(n + a->cap, 0, (size_t)(ncap - a->cap) * sizeof(ac_node_t));
        a->nodes = n;
        a->cap = ncap;
    }
    int id = a->count++;
    a->nodes[id].fail     = 0;
    a->nodes[id].sig      = -1;
    a->nodes[id].out_link = -1;
    return id;
}

/* Binary search over a node's sorted edges. */
static int ac_edge(const ac_node_t *n, uint8_t c) {
    int lo = 0, hi = (int)n->nedges - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (n->echar[mid] == c) return n->enext[mid];
        if (n->echar[mid] <  c) lo = mid + 1;
        else                    hi = mid - 1;
    }
    return -1;
}

static int ac_add_edge(ac_t *a, int node, uint8_t c, int target) {
    ac_node_t *n = &a->nodes[node];

    uint8_t  *ec = realloc(n->echar, (size_t)n->nedges + 1);
    if (!ec) return -1;
    n->echar = ec;
    int32_t  *en = realloc(n->enext, ((size_t)n->nedges + 1) * sizeof(int32_t));
    if (!en) return -1;
    n->enext = en;

    /* Keep the edges sorted so lookups can binary search. */
    int i = (int)n->nedges;
    while (i > 0 && n->echar[i-1] > c) {
        n->echar[i] = n->echar[i-1];
        n->enext[i] = n->enext[i-1];
        i--;
    }
    n->echar[i] = c;
    n->enext[i] = target;
    n->nedges++;
    return 0;
}

int ac_add(ac_t *a, const unsigned char *pat, int len, int sig_index) {
    if (!pat || len <= 0) return -1;

    int cur = 0;
    for (int i = 0; i < len; i++) {
        int nxt = ac_edge(&a->nodes[cur], pat[i]);
        if (nxt < 0) {
            nxt = ac_new_node(a);
            if (nxt < 0) return -1;
            if (ac_add_edge(a, cur, pat[i], nxt) != 0) return -1;
        }
        cur = nxt;
    }

    /*
     * Two signatures with the same pattern: the first keeps the node. The
     * second still matches through its own post-checks only if it shares
     * that node, so duplicate content across signatures is reported once.
     * Worth knowing rather than silently losing the second.
     */
    if (a->nodes[cur].sig < 0) {
        a->nodes[cur].sig = sig_index;
        a->patterns++;
    }
    a->built = false;
    return 0;
}

int ac_build(ac_t *a) {
    if (a->count <= 1) { a->built = true; return 0; }

    int *queue = malloc((size_t)a->count * sizeof(int));
    if (!queue) return -1;
    int head = 0, tail = 0;

    /* Depth-1 nodes fail to the root. */
    for (int i = 0; i < a->nodes[0].nedges; i++) {
        int child = a->nodes[0].enext[i];
        a->nodes[child].fail = 0;
        queue[tail++] = child;
    }

    while (head < tail) {
        int cur = queue[head++];
        ac_node_t *n = &a->nodes[cur];

        for (int i = 0; i < n->nedges; i++) {
            uint8_t c = n->echar[i];
            int child = n->enext[i];

            /* Follow fail links until a node has an edge on c. */
            int f = n->fail;
            int target;
            while ((target = ac_edge(&a->nodes[f], c)) < 0 && f != 0)
                f = a->nodes[f].fail;
            a->nodes[child].fail = (target >= 0 && target != child) ? target : 0;

            /*
             * The output chain lets one match report every pattern that is a
             * suffix of it, without walking the fail links at match time.
             */
            int ff = a->nodes[child].fail;
            a->nodes[child].out_link =
                (a->nodes[ff].sig >= 0) ? ff : a->nodes[ff].out_link;

            queue[tail++] = child;
        }
    }

    free(queue);
    a->built = true;
    return 0;
}

int ac_search(const ac_t *a, const unsigned char *text, int len,
              ac_cb cb, void *user) {
    if (!a->built || !text || len <= 0 || a->count <= 1) return 0;

    int cur = 0, found = 0;
    for (int i = 0; i < len; i++) {
        uint8_t c = text[i];

        int nxt;
        while ((nxt = ac_edge(&a->nodes[cur], c)) < 0 && cur != 0)
            cur = a->nodes[cur].fail;
        cur = (nxt >= 0) ? nxt : 0;

        if (a->nodes[cur].sig >= 0) {
            if (cb) cb(a->nodes[cur].sig, i, user);
            found++;
        }
        for (int o = a->nodes[cur].out_link; o >= 0; o = a->nodes[o].out_link) {
            if (cb) cb(a->nodes[o].sig, i, user);
            found++;
        }
    }
    return found;
}

/* ═══════════════════ signatures ═══════════════════ */

static const char *CLASS_NAMES[SIG_CLASS_MAX] = {
    "malware", "c2", "exploit", "recon", "dos", "policy"
};

const char *sig_class_name(sig_class_t c) {
    return ((unsigned)c < SIG_CLASS_MAX) ? CLASS_NAMES[c] : "unknown";
}

sig_class_t sig_class_from(const char *s) {
    if (!s) return SIG_CLASS_POLICY;
    for (int i = 0; i < SIG_CLASS_MAX; i++)
        if (!strcasecmp(s, CLASS_NAMES[i])) return (sig_class_t)i;
    return SIG_CLASS_POLICY;
}

const char *sig_action_name(sig_action_t a) {
    switch (a) {
        case SIG_DROP:   return "drop";
        case SIG_REJECT: return "reject";
        default:         return "alert";
    }
}

sig_action_t sig_action_from(const char *s) {
    if (!s) return SIG_ALERT;
    if (!strcasecmp(s, "drop"))   return SIG_DROP;
    if (!strcasecmp(s, "reject")) return SIG_REJECT;
    return SIG_ALERT;
}

int ids_init(ids_ctx_t *c) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);
    if (ac_init(&c->exact) != 0)  return -1;
    if (ac_init(&c->folded) != 0) { ac_free(&c->exact); return -1; }
    return 0;
}

void ids_shutdown(ids_ctx_t *c) {
    if (!c) return;
    ac_free(&c->exact);
    ac_free(&c->folded);
    pthread_mutex_destroy(&c->lock);
}

int ids_add(ids_ctx_t *c, const ids_sig_t *s) {
    if (!s || s->content_len <= 0 || s->content_len > IDS_PATTERN_LEN) return -1;

    pthread_mutex_lock(&c->lock);
    if (c->sig_count >= IDS_MAX_SIGS) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    for (int i = 0; i < c->sig_count; i++)
        if (c->sigs[i].sid == s->sid) {
            pthread_mutex_unlock(&c->lock);
            return -1;
        }

    int idx = c->sig_count;
    c->sigs[idx] = *s;
    c->sigs[idx].enabled = true;
    c->sigs[idx].hits = 0;
    if (c->sigs[idx].severity < 1) c->sigs[idx].severity = 1;
    if (c->sigs[idx].severity > 4) c->sigs[idx].severity = 4;
    c->sig_count++;

    int rc;
    if (s->nocase) {
        unsigned char low[IDS_PATTERN_LEN];
        for (int i = 0; i < s->content_len; i++)
            low[i] = (unsigned char)tolower(s->content[i]);
        rc = ac_add(&c->folded, low, s->content_len, idx);
    } else {
        rc = ac_add(&c->exact, s->content, s->content_len, idx);
    }
    pthread_mutex_unlock(&c->lock);
    return rc;
}

int ids_compile(ids_ctx_t *c) {
    pthread_mutex_lock(&c->lock);
    int rc = ac_build(&c->exact);
    if (rc == 0) rc = ac_build(&c->folded);
    pthread_mutex_unlock(&c->lock);

    if (rc == 0)
        printf("[%s] IDS: %d signature(s) compiled into %d + %d states\n",
               BRAND_PRODUCT, c->sig_count, c->exact.count, c->folded.count);
    return rc;
}

/* ═══════════════════ rule parsing ═══════════════════ */

/* Unescapes a content string. "|90 90|" is hex, anything else is literal. */
static int parse_content(const char *in, unsigned char *out, int outmax,
                         char *why, size_t whylen) {
    int o = 0;
    bool hex = false;
    int hi = -1;

    for (const char *p = in; *p; p++) {
        if (*p == '|') {
            if (hex && hi >= 0) {
                snprintf(why, whylen, "odd number of hex digits in content");
                return -1;
            }
            hex = !hex;
            continue;
        }
        if (o >= outmax) {
            snprintf(why, whylen, "content longer than %d bytes", outmax);
            return -1;
        }
        if (hex) {
            if (isspace((unsigned char)*p)) continue;
            if (!isxdigit((unsigned char)*p)) {
                snprintf(why, whylen, "'%c' is not a hex digit", *p);
                return -1;
            }
            int v = isdigit((unsigned char)*p) ? *p - '0'
                  : (tolower((unsigned char)*p) - 'a' + 10);
            if (hi < 0) { hi = v; }
            else { out[o++] = (unsigned char)((hi << 4) | v); hi = -1; }
        } else if (*p == '\\' && p[1]) {
            p++;
            out[o++] = (unsigned char)*p;
        } else {
            out[o++] = (unsigned char)*p;
        }
    }
    if (hex) { snprintf(why, whylen, "unterminated hex block in content"); return -1; }
    if (hi >= 0) { snprintf(why, whylen, "odd number of hex digits"); return -1; }
    if (o == 0) { snprintf(why, whylen, "content is empty"); return -1; }
    return o;
}

/* Pulls option:"value" or option:value out of the parenthesised body. */
static bool opt_str(const char *body, const char *key, char *out, size_t outlen) {
    char pat[32];
    int pl = snprintf(pat, sizeof(pat), "%s:", key);
    if (pl <= 0) return false;

    for (const char *p = body; (p = strstr(p, pat)) != NULL; p += pl) {
        /* Must start an option, so "content:" never matches "xcontent:". */
        if (p != body) {
            char prev = p[-1];
            if (prev != ' ' && prev != ';' && prev != '\t' && prev != '(') continue;
        }
        const char *v = p + pl;
        while (*v == ' ') v++;

        size_t o = 0;
        if (*v == '"') {
            v++;
            while (*v && *v != '"' && o + 1 < outlen) {
                if (*v == '\\' && v[1]) v++;
                out[o++] = *v++;
            }
            if (*v != '"') return false;      /* unterminated */
        } else {
            while (*v && *v != ';' && *v != ' ' && o + 1 < outlen) out[o++] = *v++;
        }
        out[o] = '\0';
        return o > 0;
    }
    return false;
}

static bool opt_flag(const char *body, const char *key) {
    size_t kl = strlen(key);
    for (const char *p = body; (p = strstr(p, key)) != NULL; p += kl) {
        if (p != body) {
            char prev = p[-1];
            if (prev != ' ' && prev != ';' && prev != '\t' && prev != '(') continue;
        }
        char next = p[kl];
        if (next == ';' || next == ' ' || next == '\0' || next == ')') return true;
    }
    return false;
}

static uint16_t parse_port(const char *s) {
    if (!s || !strcasecmp(s, "any") || !strcmp(s, "*")) return 0;
    int v = atoi(s);
    return (v > 0 && v < 65536) ? (uint16_t)v : 0;
}

int ids_parse_rule(const char *line, ids_sig_t *out, char *why, size_t whylen) {
    if (why && whylen) why[0] = '\0';
    if (!line || !out) return -1;

    memset(out, 0, sizeof(*out));
    out->enabled = true;
    out->severity = 2;
    out->rev = 1;

    char action[16] = "", proto[16] = "", sip[64] = "", sport[16] = "";
    char arrow[4] = "", dip[64] = "", dport[16] = "";

    if (sscanf(line, "%15s %15s %63s %15s %3s %63s %15s",
               action, proto, sip, sport, arrow, dip, dport) != 7) {
        snprintf(why, whylen,
                 "expected 'action proto src sport -> dst dport (options)'");
        return -1;
    }
    if (strcmp(arrow, "->") != 0) {
        snprintf(why, whylen, "expected '->' between the endpoints");
        return -1;
    }

    out->action = sig_action_from(action);
    if (strcasecmp(action, "alert") && strcasecmp(action, "drop") &&
        strcasecmp(action, "reject")) {
        snprintf(why, whylen, "unknown action '%s'", action);
        return -1;
    }

    if      (!strcasecmp(proto, "tcp"))  out->protocol = 6;
    else if (!strcasecmp(proto, "udp"))  out->protocol = 17;
    else if (!strcasecmp(proto, "icmp")) out->protocol = 1;
    else if (!strcasecmp(proto, "ip") || !strcasecmp(proto, "any")) out->protocol = 0;
    else { snprintf(why, whylen, "unknown protocol '%s'", proto); return -1; }

    out->src_port = parse_port(sport);
    out->dst_port = parse_port(dport);

    const char *body = strchr(line, '(');
    if (!body) {
        snprintf(why, whylen, "no option block; expected '( ... )'");
        return -1;
    }

    char buf[1024];
    if (!opt_str(body, "content", buf, sizeof(buf))) {
        snprintf(why, whylen, "a content option is required");
        return -1;
    }
    int n = parse_content(buf, out->content, IDS_PATTERN_LEN, why, whylen);
    if (n < 0) return -1;
    out->content_len = n;

    if (!opt_str(body, "msg", out->msg, IDS_MSG_LEN))
        snprintf(out->msg, IDS_MSG_LEN, "unnamed signature");
    opt_str(body, "reference", out->reference, IDS_REF_LEN);

    if (opt_str(body, "sid", buf, sizeof(buf))) out->sid = atoi(buf);
    if (out->sid <= 0) {
        snprintf(why, whylen, "a positive sid is required");
        return -1;
    }
    if (opt_str(body, "rev", buf, sizeof(buf)))      out->rev = atoi(buf);
    if (opt_str(body, "offset", buf, sizeof(buf)))   out->offset = atoi(buf);
    if (opt_str(body, "depth", buf, sizeof(buf)))    out->depth = atoi(buf);
    if (opt_str(body, "severity", buf, sizeof(buf))) out->severity = atoi(buf);
    if (opt_str(body, "class", buf, sizeof(buf)))    out->cls = sig_class_from(buf);

    out->nocase = opt_flag(body, "nocase");

    if (out->offset < 0 || out->depth < 0) {
        snprintf(why, whylen, "offset and depth cannot be negative");
        return -1;
    }
    if (out->depth && out->depth < out->content_len) {
        snprintf(why, whylen,
                 "depth %d cannot hold a %d byte pattern, so this rule can "
                 "never match", out->depth, out->content_len);
        return -1;
    }
    if (out->severity < 1) out->severity = 1;
    if (out->severity > 4) out->severity = 4;
    return 0;
}

int ids_load_file(ids_ctx_t *c, const char *path, int *bad) {
    if (bad) *bad = 0;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[2048], why[192];
    int loaded = 0, rejected = 0, lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        ids_sig_t s;
        if (ids_parse_rule(p, &s, why, sizeof(why)) != 0) {
            fprintf(stderr, "[%s] %s:%d: %s\n", BRAND_PRODUCT, path, lineno, why);
            rejected++;
            continue;
        }
        if (ids_add(c, &s) != 0) {
            fprintf(stderr, "[%s] %s:%d: sid %d is duplicate or the table is "
                    "full\n", BRAND_PRODUCT, path, lineno, s.sid);
            rejected++;
            continue;
        }
        loaded++;
    }
    fclose(f);
    if (bad) *bad = rejected;
    return loaded;
}

/* ═══════════════════ scanning ═══════════════════ */

struct scan_ctx {
    ids_ctx_t          *c;
    const unsigned char *payload;
    int                 len;
    uint8_t             proto;
    uint16_t            sport, dport;
    ids_hit_t          *hits;
    int                 max, n;
};

static void on_match(int sig_index, int end, void *user) {
    struct scan_ctx *s = user;
    if (sig_index < 0 || sig_index >= s->c->sig_count) return;

    ids_sig_t *sig = &s->c->sigs[sig_index];
    if (!sig->enabled) return;

    /* Post-checks the automaton cannot express. */
    if (sig->protocol && sig->protocol != s->proto) return;
    if (sig->src_port && sig->src_port != s->sport) return;
    if (sig->dst_port && sig->dst_port != s->dport) return;

    int start = end - sig->content_len + 1;
    if (start < sig->offset) return;
    if (sig->depth && end >= sig->offset + sig->depth) return;

    /* One signature reports once per packet, however often it matches. */
    for (int i = 0; i < s->n; i++)
        if (s->hits[i].sid == sig->sid) return;

    sig->hits++;
    sig->last_hit = time(NULL);

    if (s->n >= s->max) return;
    s->hits[s->n].sid      = sig->sid;
    s->hits[s->n].cls      = sig->cls;
    s->hits[s->n].action   = sig->action;
    s->hits[s->n].severity = sig->severity;
    s->hits[s->n].msg      = sig->msg;
    s->hits[s->n].offset   = start;
    s->n++;
}

int ids_scan(ids_ctx_t *c, const unsigned char *payload, int len,
             uint8_t proto, uint16_t sport, uint16_t dport,
             ids_hit_t *hits, int max) {
    if (!c->enabled || !payload || len <= 0 || !hits || max <= 0) return 0;

    pthread_mutex_lock(&c->lock);
    c->scanned++;

    struct scan_ctx s = {
        .c = c, .payload = payload, .len = len,
        .proto = proto, .sport = sport, .dport = dport,
        .hits = hits, .max = max, .n = 0
    };

    ac_search(&c->exact, payload, len, on_match, &s);

    /* Case-insensitive patterns match a folded copy of the payload. */
    if (c->folded.patterns > 0) {
        unsigned char stackbuf[2048];
        unsigned char *low = (len <= (int)sizeof(stackbuf))
                           ? stackbuf : malloc((size_t)len);
        if (low) {
            for (int i = 0; i < len; i++)
                low[i] = (unsigned char)tolower(payload[i]);
            ac_search(&c->folded, low, len, on_match, &s);
            if (low != stackbuf) free(low);
        }
    }

    if (s.n) c->matched++;
    pthread_mutex_unlock(&c->lock);

    /* Worst first, so a caller that only looks at hits[0] sees the worst. */
    for (int i = 1; i < s.n; i++) {
        ids_hit_t k = hits[i];
        int j = i - 1;
        while (j >= 0 && hits[j].severity < k.severity) {
            hits[j+1] = hits[j];
            j--;
        }
        hits[j+1] = k;
    }
    return s.n;
}

sig_action_t ids_verdict(const ids_ctx_t *c, const ids_hit_t *hits, int n) {
    if (n <= 0) return SIG_ALERT;

    sig_action_t worst = SIG_ALERT;
    for (int i = 0; i < n; i++)
        if (hits[i].action > worst) worst = hits[i].action;

    /* Out of inline mode the engine only ever reports; a rule that says drop
     * still only alerts, which is how you deploy a new ruleset safely. */
    if (!c->inline_mode) return SIG_ALERT;
    return worst;
}
