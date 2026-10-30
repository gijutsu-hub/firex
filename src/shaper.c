/*
 * Traffic shaping. See include/shaper.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "shaper.h"
#include "netconf.h"
#include "netutil.h"
#include "shellcmd.h"
#include "brand.h"

const char *qdisc_name(qdisc_t q) {
    switch (q) {
        case QDISC_CAKE:        return "cake";
        case QDISC_SFQ:         return "sfq";
        case QDISC_PFIFO_FAST:  return "pfifo_fast";
        default:                return "fq_codel";
    }
}

qdisc_t qdisc_from(const char *s) {
    if (!s) return QDISC_FQ_CODEL;
    if (!strcasecmp(s, "cake"))       return QDISC_CAKE;
    if (!strcasecmp(s, "sfq"))        return QDISC_SFQ;
    if (!strcasecmp(s, "pfifo_fast") ||
        !strcasecmp(s, "none"))       return QDISC_PFIFO_FAST;
    return QDISC_FQ_CODEL;
}

int shaper_init(shaper_ctx_t *s, const shaper_cfg_t *cfg) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
    if (cfg) s->cfg = *cfg;
    if (!s->cfg.codel_target_ms)   s->cfg.codel_target_ms = 5;
    if (!s->cfg.codel_interval_ms) s->cfg.codel_interval_ms = 100;
    return 0;
}

void shaper_shutdown(shaper_ctx_t *s) {
    if (!s) return;
    pthread_mutex_destroy(&s->lock);
}

/* ── plan building ──────────────────────────────────────────────────── */

static void emit(shaper_plan_t *p, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void emit(shaper_plan_t *p, const char *fmt, ...) {
    if (p->count >= SHAPER_MAX_CMDS) { p->overflow++; return; }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(p->cmd[p->count], SHAPER_CMD_LEN, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= SHAPER_CMD_LEN) { p->overflow++; return; }
    p->count++;
}

/* The leaf qdisc under an HTB class. This is where the latency is won or
 * lost, so the parameters are spelled out rather than left to defaults. */
/*
 * `where` is a complete attachment point -- "root" or "parent 1:100" -- not a
 * fragment. tc rejects "parent root", and attaching a leaf to the root qdisc
 * handle rather than to a class silently gives every class the default
 * qdisc instead of this one.
 */
static void emit_leaf(shaper_plan_t *p, const shaper_cfg_t *c,
                      const char *dev, const char *where, int handle) {
    switch (c->qdisc) {
        case QDISC_CAKE:
            emit(p, "tc qdisc replace dev %s %s handle %d: cake besteffort %s",
                 dev, where, handle, c->ecn ? "ecn" : "noecn");
            break;
        case QDISC_SFQ:
            emit(p, "tc qdisc replace dev %s %s handle %d: sfq perturb 10",
                 dev, where, handle);
            break;
        case QDISC_PFIFO_FAST:
            emit(p, "tc qdisc replace dev %s %s handle %d: pfifo_fast",
                 dev, where, handle);
            break;
        default:
            emit(p, "tc qdisc replace dev %s %s handle %d: fq_codel "
                    "target %dms interval %dms %s",
                 dev, where, handle, c->codel_target_ms,
                 c->codel_interval_ms, c->ecn ? "ecn" : "noecn");
            break;
    }
}

/* How many VLANs get a class of their own on the WAN. */
static int shaped_vlan_count(vlan_ctx_t *v) {
    int n = 0;
    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *c = &v->vlans[i];
        if (c->enabled && (c->bandwidth_up_mbps || c->bandwidth_down_mbps)) n++;
    }
    return n;
}

int shaper_classid_for(vlan_ctx_t *v, uint16_t vlan_id) {
    int idx = 0;
    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *c = &v->vlans[i];
        if (!c->enabled) continue;
        if (!c->bandwidth_up_mbps && !c->bandwidth_down_mbps) continue;
        if (c->vlan_id == vlan_id) return SHAPER_BASE_CLASS + idx;
        idx++;
    }
    return SHAPER_DEF_CLASS;
}

/* The interface a VLAN's own traffic leaves on: its sub-interface of the
 * trunk port that carries it. */
static bool vlan_iface(vlan_ctx_t *v, uint16_t vid, char *out, size_t len) {
    for (int i = 0; i < v->port_count; i++) {
        port_config_t *p = &v->ports[i];
        if (p->mode != PORT_MODE_TRUNK && p->mode != PORT_MODE_HYBRID) continue;
        if (!port_vlan_permitted(p, vid)) continue;
        if (!fx_ifname_safe(p->ifname, IFNAME_LEN)) continue;
        snprintf(out, len, "%s.%u", p->ifname, vid);
        return true;
    }
    /* An access port carries its PVID untagged, so the port itself is the
     * interface. */
    for (int i = 0; i < v->port_count; i++) {
        port_config_t *p = &v->ports[i];
        if (p->mode != PORT_MODE_ACCESS || p->pvid != vid) continue;
        if (!fx_ifname_safe(p->ifname, IFNAME_LEN)) continue;
        snprintf(out, len, "%s", p->ifname);
        return true;
    }
    return false;
}

int shaper_plan(const shaper_cfg_t *cfg, vlan_ctx_t *v, netconf_ctx_t *n,
                shaper_plan_t *out) {
    if (!cfg || !v || !n || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (!cfg->enabled) return 0;

    char sbuf[INET_ADDRSTRLEN], dev[IFNAME_LEN * 2];

    /* ── WAN egress: upload, with one class per shaped VLAN ── */
    for (int w = 0; w < n->wan_count; w++) {
        wan_config_t *wan = &n->wan[w];
        if (wan->mode == WAN_DISABLED) continue;
        if (!fx_ifname_safe(wan->ifname, IFNAME_LEN)) continue;

        emit(out, "tc qdisc del dev %s root 2>/dev/null", wan->ifname);

        if (cfg->wan_up_mbps <= 0) {
            /* No ceiling to enforce, but the leaf qdisc is still worth
             * having: it is what keeps a saturated uplink responsive. */
            emit_leaf(out, cfg, wan->ifname, "root", 1);
            continue;
        }

        emit(out, "tc qdisc add dev %s root handle 1: htb default %d",
             wan->ifname, SHAPER_DEF_CLASS);
        emit(out, "tc class add dev %s parent 1: classid 1:%d htb "
                  "rate %dmbit ceil %dmbit",
             wan->ifname, SHAPER_ROOT_CLASS, cfg->wan_up_mbps, cfg->wan_up_mbps);

        /*
         * HTB's `rate` is a guarantee, and the children's guarantees must
         * not exceed the parent's. A VLAN with no explicit upload limit
         * therefore gets an even share of what is left rather than the whole
         * ceiling -- it can still borrow up to `ceil` when the link is idle.
         */
        int shaped = shaped_vlan_count(v);
        int explicit_total = 0, implicit = 0;
        for (int i = 0; i < v->vlan_count; i++) {
            vlan_config_t *c = &v->vlans[i];
            if (!c->enabled) continue;
            if (!c->bandwidth_up_mbps && !c->bandwidth_down_mbps) continue;
            if (c->bandwidth_up_mbps > 0) explicit_total += c->bandwidth_up_mbps;
            else                          implicit++;
        }

        /* A tenth of the link is held back for anything unclassified. */
        int reserve = cfg->wan_up_mbps > 10 ? cfg->wan_up_mbps / 10 : 1;
        int spare   = cfg->wan_up_mbps - reserve - explicit_total;
        if (spare < 0) spare = 0;
        int share = implicit > 0 ? spare / implicit : 0;
        if (implicit > 0 && share < 1) share = 1;

        int classid = SHAPER_BASE_CLASS;
        char where[32];

        for (int i = 0; i < v->vlan_count; i++) {
            vlan_config_t *c = &v->vlans[i];
            if (!c->enabled) continue;
            if (!c->bandwidth_up_mbps && !c->bandwidth_down_mbps) continue;

            int up = c->bandwidth_up_mbps > 0 ? c->bandwidth_up_mbps : share;
            if (up > cfg->wan_up_mbps) up = cfg->wan_up_mbps;
            if (up < 1) up = 1;

            /* 802.1p runs 0 (lowest) to 7; tc prio runs 0 (highest) to 7.
             * Invert so a high-priority VLAN really is served first. */
            int prio = 7 - (c->priority > 7 ? 7 : c->priority);

            emit(out, "tc class add dev %s parent 1:%d classid 1:%d htb "
                      "rate %dmbit ceil %dmbit prio %d",
                 wan->ifname, SHAPER_ROOT_CLASS, classid, up,
                 cfg->wan_up_mbps, prio);

            snprintf(where, sizeof(where), "parent 1:%d", classid);
            emit_leaf(out, cfg, wan->ifname, where, classid);

            if (c->subnet && c->netmask)
                emit(out, "tc filter add dev %s protocol ip parent 1: prio 1 "
                          "u32 match ip src %s/%d flowid 1:%d",
                     wan->ifname,
                     fx_ip_str(c->subnet, sbuf, sizeof(sbuf)),
                     fx_netmask_to_cidr(c->netmask), classid);
            classid++;
        }
        (void)shaped;

        /* Everything unclassified gets the reserve and may borrow the rest,
         * so an unlisted VLAN is slowed, never starved. */
        emit(out, "tc class add dev %s parent 1:%d classid 1:%d htb "
                  "rate %dmbit ceil %dmbit prio 7",
             wan->ifname, SHAPER_ROOT_CLASS, SHAPER_DEF_CLASS,
             reserve, cfg->wan_up_mbps);
        snprintf(where, sizeof(where), "parent 1:%d", SHAPER_DEF_CLASS);
        emit_leaf(out, cfg, wan->ifname, where, SHAPER_DEF_CLASS);
    }

    /* ── Per-VLAN egress: download toward that VLAN's clients ── */
    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *c = &v->vlans[i];
        if (!c->enabled) continue;
        if (!vlan_iface(v, c->vlan_id, dev, sizeof(dev))) continue;

        emit(out, "tc qdisc del dev %s root 2>/dev/null", dev);

        if (c->bandwidth_down_mbps > 0) {
            char where[32];
            emit(out, "tc qdisc add dev %s root handle 1: htb default %d",
                 dev, SHAPER_BASE_CLASS);
            emit(out, "tc class add dev %s parent 1: classid 1:%d htb "
                      "rate %dmbit ceil %dmbit",
                 dev, SHAPER_BASE_CLASS, c->bandwidth_down_mbps,
                 c->bandwidth_down_mbps);
            snprintf(where, sizeof(where), "parent 1:%d", SHAPER_BASE_CLASS);
            emit_leaf(out, cfg, dev, where, SHAPER_BASE_CLASS);
        } else {
            /* No ceiling for this segment, but the leaf qdisc still earns
             * its place: it is what keeps the link responsive under load. */
            emit_leaf(out, cfg, dev, "root", 1);
        }
    }

    /* ── WAN ingress via IFB: total download ── */
    if (cfg->ingress_shaping && cfg->wan_down_mbps > 0 && n->wan_count > 0) {
        wan_config_t *wan = &n->wan[0];
        if (fx_ifname_safe(wan->ifname, IFNAME_LEN)) {
            emit(out, "modprobe ifb numifbs=1 2>/dev/null");
            emit(out, "ip link add %s type ifb 2>/dev/null", SHAPER_IFB_DEV);
            emit(out, "ip link set %s up", SHAPER_IFB_DEV);

            emit(out, "tc qdisc del dev %s ingress 2>/dev/null", wan->ifname);
            emit(out, "tc qdisc add dev %s handle ffff: ingress", wan->ifname);
            emit(out, "tc filter add dev %s parent ffff: protocol all prio 1 "
                      "u32 match u32 0 0 action mirred egress redirect dev %s",
                 wan->ifname, SHAPER_IFB_DEV);

            emit(out, "tc qdisc del dev %s root 2>/dev/null", SHAPER_IFB_DEV);
            emit(out, "tc qdisc add dev %s root handle 1: htb default %d",
                 SHAPER_IFB_DEV, SHAPER_BASE_CLASS);
            emit(out, "tc class add dev %s parent 1: classid 1:%d htb "
                      "rate %dmbit ceil %dmbit",
                 SHAPER_IFB_DEV, SHAPER_BASE_CLASS,
                 cfg->wan_down_mbps, cfg->wan_down_mbps);
            char ifbwhere[32];
            snprintf(ifbwhere, sizeof(ifbwhere), "parent 1:%d",
                     SHAPER_BASE_CLASS);
            emit_leaf(out, cfg, SHAPER_IFB_DEV, ifbwhere, SHAPER_BASE_CLASS);
        }
    }

    return out->count;
}

int shaper_plan_teardown(const shaper_cfg_t *cfg, vlan_ctx_t *v,
                         netconf_ctx_t *n, shaper_plan_t *out) {
    if (!v || !n || !out) return -1;
    memset(out, 0, sizeof(*out));

    char dev[IFNAME_LEN * 2];

    for (int w = 0; w < n->wan_count; w++) {
        wan_config_t *wan = &n->wan[w];
        if (!fx_ifname_safe(wan->ifname, IFNAME_LEN)) continue;
        emit(out, "tc qdisc del dev %s root 2>/dev/null", wan->ifname);
        emit(out, "tc qdisc del dev %s ingress 2>/dev/null", wan->ifname);
    }

    for (int i = 0; i < v->vlan_count; i++) {
        if (!vlan_iface(v, v->vlans[i].vlan_id, dev, sizeof(dev))) continue;
        emit(out, "tc qdisc del dev %s root 2>/dev/null", dev);
    }

    if (cfg && cfg->ingress_shaping) {
        emit(out, "tc qdisc del dev %s root 2>/dev/null", SHAPER_IFB_DEV);
        emit(out, "ip link del %s 2>/dev/null", SHAPER_IFB_DEV);
    }
    return out->count;
}

/* ── running ────────────────────────────────────────────────────────── */

int shaper_run(shaper_ctx_t *s, const shaper_plan_t *p) {
    unsigned before = fx_run_failures();

    for (int i = 0; i < p->count; i++) {
        /* A command already carrying 2>/dev/null is one that is expected to
         * fail routinely -- deleting a qdisc that was never added. */
        if (strstr(p->cmd[i], "2>/dev/null")) fx_try(p->cmd[i]);
        else                                  fx_run(p->cmd[i]);
    }

    unsigned failed = fx_run_failures() - before;
    pthread_mutex_lock(&s->lock);
    s->failures += failed;
    pthread_mutex_unlock(&s->lock);
    return (int)failed;
}

int shaper_apply(shaper_ctx_t *s, vlan_ctx_t *v, netconf_ctx_t *n) {
    if (!s->cfg.enabled) return 0;

    shaper_plan_t *plan = calloc(1, sizeof(*plan));
    if (!plan) return -1;

    int cmds = shaper_plan(&s->cfg, v, n, plan);
    if (cmds <= 0) { free(plan); return 0; }

    if (plan->overflow)
        fprintf(stderr, "[%s] shaping: %d command(s) did not fit the plan; "
                "the hierarchy will be incomplete\n",
                BRAND_PRODUCT, plan->overflow);

    printf("[%s] Shaping: %s, %d command(s)\n", BRAND_PRODUCT,
           qdisc_name(s->cfg.qdisc), cmds);

    int failed = shaper_run(s, plan);

    pthread_mutex_lock(&s->lock);
    s->applied = true;
    s->classes = 0;
    for (int i = 0; i < v->vlan_count; i++)
        if (v->vlans[i].enabled &&
            (v->vlans[i].bandwidth_up_mbps || v->vlans[i].bandwidth_down_mbps))
            s->classes++;
    s->ifaces_shaped = n->wan_count;
    if (failed)
        snprintf(s->last_error, sizeof(s->last_error),
                 "%d tc command(s) failed; is the kernel's sch_%s module "
                 "available?", failed, qdisc_name(s->cfg.qdisc));
    else
        s->last_error[0] = '\0';
    pthread_mutex_unlock(&s->lock);

    if (s->cfg.wan_up_mbps > 0)
        printf("  [SHAPE] upload ceiling %d Mbit, %d VLAN class(es)\n",
               s->cfg.wan_up_mbps, s->classes);
    if (s->cfg.ingress_shaping && s->cfg.wan_down_mbps > 0)
        printf("  [SHAPE] download ceiling %d Mbit via %s\n",
               s->cfg.wan_down_mbps, SHAPER_IFB_DEV);

    free(plan);
    return failed;
}

int shaper_teardown(shaper_ctx_t *s, vlan_ctx_t *v, netconf_ctx_t *n) {
    shaper_plan_t *plan = calloc(1, sizeof(*plan));
    if (!plan) return -1;

    shaper_plan_teardown(&s->cfg, v, n, plan);
    for (int i = 0; i < plan->count; i++) fx_try(plan->cmd[i]);

    pthread_mutex_lock(&s->lock);
    s->applied = false;
    pthread_mutex_unlock(&s->lock);

    free(plan);
    return 0;
}
