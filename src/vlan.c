#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "vlan.h"
#include "shellcmd.h"

#define fx_ifname_safe2(n) fx_ifname_safe((n), IFNAME_LEN)

static const char *ZONE_NAMES[ZONE_MAX] = {
    "WAN", "LAN", "DMZ", "GUEST", "IOT", "VOIP", "MGMT", "QUARANTINE", "VPN"
};

const char *zone_name(zone_t z) {
    return ((unsigned)z < ZONE_MAX) ? ZONE_NAMES[z] : "UNKNOWN";
}

const char *port_mode_name(port_mode_t m) {
    switch (m) {
        case PORT_MODE_ACCESS:   return "ACCESS";
        case PORT_MODE_TRUNK:    return "TRUNK";
        case PORT_MODE_HYBRID:   return "HYBRID";
        case PORT_MODE_MIRROR:   return "MIRROR";
        default:                 return "DISABLED";
    }
}

/* ═══════════ DEFAULT ENTERPRISE ZONE MATRIX ═══════════
 * Rows = source zone, Cols = destination zone.
 * Deny-by-default posture with explicit business allows.
 */
static void install_default_matrix(vlan_ctx_t *v) {
    for (int f = 0; f < ZONE_MAX; f++)
        for (int t = 0; t < ZONE_MAX; t++)
            v->zone_matrix[f][t] = IVR_DENY;

    /* LAN (corporate) */
    v->zone_matrix[ZONE_LAN][ZONE_WAN]   = IVR_ALLOW;
    v->zone_matrix[ZONE_LAN][ZONE_DMZ]   = IVR_ALLOW;
    v->zone_matrix[ZONE_LAN][ZONE_VOIP]  = IVR_ALLOW;
    v->zone_matrix[ZONE_LAN][ZONE_IOT]   = IVR_LOG_ALLOW;
    v->zone_matrix[ZONE_LAN][ZONE_LAN]   = IVR_ALLOW;

    /* DMZ - may answer outward, may not initiate inward */
    v->zone_matrix[ZONE_DMZ][ZONE_WAN]   = IVR_LOG_ALLOW;
    v->zone_matrix[ZONE_DMZ][ZONE_DMZ]   = IVR_ALLOW;

    /* GUEST - internet only, fully isolated internally */
    v->zone_matrix[ZONE_GUEST][ZONE_WAN] = IVR_LOG_ALLOW;

    /* IOT - no internet by default, talks only to the DMZ controller */
    v->zone_matrix[ZONE_IOT][ZONE_DMZ]   = IVR_LOG_ALLOW;

    /* VOIP - internet (SIP trunk) + LAN */
    v->zone_matrix[ZONE_VOIP][ZONE_WAN]  = IVR_ALLOW;
    v->zone_matrix[ZONE_VOIP][ZONE_LAN]  = IVR_ALLOW;
    v->zone_matrix[ZONE_VOIP][ZONE_VOIP] = IVR_ALLOW;

    /* MGMT - full reach, always logged */
    for (int t = 0; t < ZONE_MAX; t++)
        v->zone_matrix[ZONE_MGMT][t] = IVR_LOG_ALLOW;

    /* QUARANTINE stays all-DENY; WAN inbound stays DENY (use DNAT). */
}

int vlan_init(vlan_ctx_t *v) {
    memset(v, 0, sizeof(*v));
    pthread_mutex_init(&v->lock, NULL);
    install_default_matrix(v);
    return 0;
}

ivr_action_t vlan_check_zones(vlan_ctx_t *v, zone_t from, zone_t to,
                              char *reason, int rlen) {
    char scratch[8];
    if (!reason || rlen <= 0) { reason = scratch; rlen = (int)sizeof(scratch); }

    if ((unsigned)from >= ZONE_MAX || (unsigned)to >= ZONE_MAX) {
        snprintf(reason, rlen, "%s-ZONE: unknown zone", BRAND_POLICY_PREFIX);
        return IVR_DENY;
    }

    pthread_mutex_lock(&v->lock);
    ivr_action_t a = (from == to) ? IVR_ALLOW : v->zone_matrix[from][to];

    snprintf(reason, rlen, "%s-ZONE: %s -> %s = %s", BRAND_POLICY_PREFIX,
             zone_name(from), zone_name(to),
             (a == IVR_DENY || a == IVR_LOG_DENY) ? "DENY" : "ALLOW");

    if (a == IVR_DENY || a == IVR_LOG_DENY) v->inter_vlan_denied++;
    else                                    v->inter_vlan_allowed++;
    pthread_mutex_unlock(&v->lock);
    return a;
}

void vlan_set_zone_policy(vlan_ctx_t *v, zone_t from, zone_t to, ivr_action_t a) {
    if ((unsigned)from < ZONE_MAX && (unsigned)to < ZONE_MAX)
        v->zone_matrix[from][to] = a;
}

/* ═══════════ VLAN MANAGEMENT ═══════════ */
void vlan_set_policy(vlan_ctx_t *v, policy_ctx_t *p) {
    pthread_mutex_lock(&v->lock);
    v->policy = p;
    pthread_mutex_unlock(&v->lock);
}

int vlan_add(vlan_ctx_t *v, vlan_config_t *cfg) {
    if (cfg->vlan_id < 1 || cfg->vlan_id > 4094) return -1;

    pthread_mutex_lock(&v->lock);
    for (int i = 0; i < v->vlan_count; i++)
        if (v->vlans[i].vlan_id == cfg->vlan_id) {
            pthread_mutex_unlock(&v->lock);
            return -2;
        }
    if (v->vlan_count >= MAX_VLANS) {
        pthread_mutex_unlock(&v->lock);
        return -3;
    }

    if (cfg->lease_time == 0) cfg->lease_time = 86400;
    cfg->enabled = true;
    v->vlans[v->vlan_count++] = *cfg;
    pthread_mutex_unlock(&v->lock);
    return 0;
}

vlan_config_t *vlan_get(vlan_ctx_t *v, uint16_t vid) {
    for (int i = 0; i < v->vlan_count; i++)
        if (v->vlans[i].vlan_id == vid) return &v->vlans[i];
    return NULL;
}

int vlan_remove(vlan_ctx_t *v, uint16_t vid) {
    pthread_mutex_lock(&v->lock);
    for (int i = 0; i < v->vlan_count; i++) {
        if (v->vlans[i].vlan_id == vid) {
            memmove(&v->vlans[i], &v->vlans[i+1],
                    (v->vlan_count - i - 1) * sizeof(vlan_config_t));
            v->vlan_count--;
            pthread_mutex_unlock(&v->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&v->lock);
    return -1;
}

/* ═══════════ PORT MANAGEMENT ═══════════ */
int port_configure(vlan_ctx_t *v, port_config_t *p) {
    pthread_mutex_lock(&v->lock);
    for (int i = 0; i < v->port_count; i++) {
        if (strcmp(v->ports[i].ifname, p->ifname) == 0) {
            v->ports[i] = *p;
            pthread_mutex_unlock(&v->lock);
            return 0;
        }
    }
    if (v->port_count >= MAX_PORTS) {
        pthread_mutex_unlock(&v->lock);
        return -1;
    }
    v->ports[v->port_count++] = *p;
    pthread_mutex_unlock(&v->lock);
    return 0;
}

port_config_t *port_get(vlan_ctx_t *v, const char *ifname) {
    if (!ifname) return NULL;
    for (int i = 0; i < v->port_count; i++)
        if (strcmp(v->ports[i].ifname, ifname) == 0) return &v->ports[i];
    return NULL;
}

bool port_vlan_permitted(port_config_t *p, uint16_t vid) {
    if (!p || !p->enabled) return false;

    switch (p->mode) {
        case PORT_MODE_ACCESS:
            return vid == p->pvid || vid == 0;
        case PORT_MODE_TRUNK:
            if (vid == 0) return !p->drop_untagged;
            for (int i = 0; i < p->allowed_count; i++)
                if (p->allowed_vlans[i] == vid) return true;
            return false;
        case PORT_MODE_HYBRID:
            if (vid == 0 || vid == p->pvid) return true;
            for (int i = 0; i < p->allowed_count; i++)
                if (p->allowed_vlans[i] == vid) return true;
            return false;
        case PORT_MODE_MIRROR:
            return true;
        default:
            return false;
    }
}

/* ═══════════ INTER-VLAN ACL ═══════════ */
int ivr_add_rule(vlan_ctx_t *v, ivr_rule_t *r) {
    pthread_mutex_lock(&v->lock);
    if (v->ivr_count >= MAX_IVR_RULES) {
        pthread_mutex_unlock(&v->lock);
        return -1;
    }
    r->id = v->ivr_count;
    r->enabled = true;
    v->ivr[v->ivr_count++] = *r;

    /* keep sorted by priority (lower = evaluated first) */
    for (int i = v->ivr_count - 1; i > 0; i--) {
        if (v->ivr[i].priority < v->ivr[i-1].priority) {
            ivr_rule_t t = v->ivr[i];
            v->ivr[i] = v->ivr[i-1];
            v->ivr[i-1] = t;
        } else break;
    }

    int id = r->id;
    pthread_mutex_unlock(&v->lock);
    return id;
}

/* Main forwarding decision: specific ACL first, then the zone matrix. */
ivr_action_t vlan_check_forward(vlan_ctx_t *v, uint16_t src_vid, uint16_t dst_vid,
                                uint32_t sip, uint32_t dip, uint16_t dport,
                                uint8_t proto, char *reason, int rlen) {
    char scratch[8];
    if (!reason || rlen <= 0) { reason = scratch; rlen = (int)sizeof(scratch); }

    pthread_mutex_lock(&v->lock);

    vlan_config_t *svl = NULL, *dvl = NULL;
    for (int i = 0; i < v->vlan_count; i++) {
        if (v->vlans[i].vlan_id == src_vid) svl = &v->vlans[i];
        if (v->vlans[i].vlan_id == dst_vid) dvl = &v->vlans[i];
    }

    /* 1. Intra-VLAN with client isolation */
    if (src_vid == dst_vid) {
        if (svl && svl->client_isolation) {
            v->inter_vlan_denied++;
            snprintf(reason, rlen, "%s-ISO-%u: client isolation on VLAN %u (%s)",
                     BRAND_POLICY_PREFIX, src_vid, src_vid,
                     svl->name[0] ? svl->name : "-");
            pthread_mutex_unlock(&v->lock);
            return IVR_DENY;
        }
        v->inter_vlan_allowed++;
        snprintf(reason, rlen, "%s-INTRA-%u: same segment", BRAND_POLICY_PREFIX,
                 src_vid);
        pthread_mutex_unlock(&v->lock);
        return IVR_ALLOW;
    }

    /* 2. Explicit ACL rules.
     *
     * These are checked before the VLAN's blanket inter_vlan_routing switch:
     * a specific rule has to be able to carve an exception out of a default
     * posture, otherwise entries like "IOT MQTT to controller" on a VLAN with
     * inter_vlan_routing=no could never match and would be silently dead. */
    time_t now = 0;
    for (int i = 0; i < v->ivr_count; i++) {
        ivr_rule_t *r = &v->ivr[i];
        if (!r->enabled) continue;
        if (r->src_vlan && r->src_vlan != src_vid) continue;
        if (r->dst_vlan && r->dst_vlan != dst_vid) continue;
        if (r->protocol && r->protocol != proto)   continue;

        /* Address match: an alias reference replaces the literal CIDR. */
        if (r->src_alias[0]) {
            if (!policy_match_ip(v->policy, r->src_alias, sip)) continue;
        } else if (r->src_ip &&
                   (sip & r->src_mask) != (r->src_ip & r->src_mask)) continue;

        if (r->dst_alias[0]) {
            if (!policy_match_ip(v->policy, r->dst_alias, dip)) continue;
        } else if (r->dst_ip &&
                   (dip & r->dst_mask) != (r->dst_ip & r->dst_mask)) continue;

        if (r->port_alias[0]) {
            if (!policy_match_port(v->policy, r->port_alias, dport)) continue;
        } else if (r->dst_port_start &&
                   (dport < r->dst_port_start || dport > r->dst_port_end)) continue;

        /*
         * Schedule is checked last, once the rule is known to match on every
         * other count: outside its window the rule is simply not there, and
         * evaluation carries on to whatever follows it.
         */
        if (r->schedule[0]) {
            if (!now) now = time(NULL);
            if (!policy_schedule_active(v->policy, r->schedule, now)) {
                v->schedule_skipped++;
                continue;
            }
        }

        r->hits++;
        snprintf(reason, rlen, "%s-%04d: %s",
                 BRAND_POLICY_PREFIX, r->id,
                 r->description[0] ? r->description : "ACL match");

        if (r->action == IVR_DENY || r->action == IVR_LOG_DENY)
            v->inter_vlan_denied++;
        else
            v->inter_vlan_allowed++;

        ivr_action_t a = r->action;
        pthread_mutex_unlock(&v->lock);
        return a;
    }

    /* 3. VLAN-level routing switch (no explicit rule claimed this flow) */
    if (svl && !svl->inter_vlan_routing) {
        v->inter_vlan_denied++;
        snprintf(reason, rlen, "%s-IVR-%u: inter-VLAN routing disabled on %s",
                 BRAND_POLICY_PREFIX, src_vid, svl->name);
        pthread_mutex_unlock(&v->lock);
        return IVR_DENY;
    }

    /* 4. Zone matrix fallback */
    zone_t sz = svl ? svl->zone : ZONE_WAN;
    zone_t dz = dvl ? dvl->zone : ZONE_WAN;
    ivr_action_t za = v->zone_matrix[sz][dz];

    snprintf(reason, rlen, "%s-ZONE: %s -> %s = %s",
             BRAND_POLICY_PREFIX, zone_name(sz), zone_name(dz),
             (za == IVR_DENY || za == IVR_LOG_DENY) ? "DENY" : "ALLOW");

    if (za == IVR_DENY || za == IVR_LOG_DENY) v->inter_vlan_denied++;
    else                                      v->inter_vlan_allowed++;

    pthread_mutex_unlock(&v->lock);
    return za;
}

/* ═══════════ SYSTEM PROVISIONING ═══════════
 * Creates real Linux 802.1Q sub-interfaces, addresses, shaping and the
 * zone-matrix FORWARD chain.
 */
int vlan_apply_to_system(vlan_ctx_t *v) {
    char cmd[512], abuf[INET_ADDRSTRLEN];

    printf("[%s] Provisioning VLAN segmentation...\n", BRAND_PRODUCT);

    for (int p = 0; p < v->port_count; p++) {
        port_config_t *port = &v->ports[p];
        if (!port->enabled) continue;
        if (!fx_ifname_safe2(port->ifname)) {
            fprintf(stderr, "[%s] refusing unsafe interface name \"%s\"\n",
                    BRAND_PRODUCT, port->ifname);
            continue;
        }

        snprintf(cmd, sizeof(cmd), "ip link set %s up", port->ifname);
        fx_run(cmd);

        if (port->mode == PORT_MODE_TRUNK || port->mode == PORT_MODE_HYBRID) {
            for (int i = 0; i < port->allowed_count; i++) {
                uint16_t vid = port->allowed_vlans[i];
                vlan_config_t *vl = vlan_get(v, vid);
                if (!vl || !vl->enabled) continue;

                /* Create the 802.1Q sub-interface, e.g. eth1.10 */
                snprintf(cmd, sizeof(cmd),
                    "ip link add link %s name %s.%u type vlan id %u 2>/dev/null",
                    port->ifname, port->ifname, vid, vid);
                fx_run(cmd);

                snprintf(cmd, sizeof(cmd), "ip link set %s.%u up",
                         port->ifname, vid);
                fx_run(cmd);

                /* Assign the SVI gateway address, unless VRRP owns it. */
                if (vl->gateway) {
                    int bits = fx_netmask_to_cidr(vl->netmask);
                    fx_ip_str(vl->gateway, abuf, sizeof(abuf));

                    if (v->ha_owns_gateways) {
                        printf("  [VLAN %4u] %-12s %s/%d on %s.%u  zone=%s  "
                               "(virtual, held by VRRP)\n",
                               vid, vl->name, abuf, bits, port->ifname, vid,
                               zone_name(vl->zone));
                    } else {
                        snprintf(cmd, sizeof(cmd),
                            "ip addr add %s/%d dev %s.%u 2>/dev/null",
                            abuf, bits, port->ifname, vid);
                        fx_run(cmd);

                        printf("  [VLAN %4u] %-12s %s/%d on %s.%u  zone=%s\n",
                               vid, vl->name, abuf, bits, port->ifname, vid,
                               zone_name(vl->zone));
                    }
                }

                /* Shaping is the shaper's job now. A token bucket here
                 * would fight it for the same root qdisc, and a single FIFO
                 * behind a rate limit leaves bufferbloat exactly where it
                 * was -- see src/shaper.c. */

                /* Client isolation: block intra-segment forwarding */
                if (vl->client_isolation) {
                    snprintf(cmd, sizeof(cmd),
                        "iptables -I FORWARD -i %s.%u -o %s.%u -j DROP",
                        port->ifname, vid, port->ifname, vid);
                    fx_run(cmd);
                }
            }
        }

        /* Access port: untagged PVID */
        if (port->mode == PORT_MODE_ACCESS && port->pvid) {
            vlan_config_t *vl = vlan_get(v, port->pvid);
            if (vl && vl->gateway) {
                int bits = fx_netmask_to_cidr(vl->netmask);
                snprintf(cmd, sizeof(cmd),
                    "ip addr add %s/%d dev %s 2>/dev/null",
                    fx_ip_str(vl->gateway, abuf, sizeof(abuf)), bits, port->ifname);
                fx_run(cmd);
                printf("  [PORT %-6s] ACCESS  PVID=%u  zone=%s\n",
                       port->ifname, port->pvid, zone_name(vl->zone));
            }
        }

        /* Broadcast storm control */
        if (port->storm_control && port->storm_pps_limit > 0) {
            snprintf(cmd, sizeof(cmd),
                "iptables -I FORWARD -i %s -m pkttype --pkt-type broadcast "
                "-m limit --limit %d/sec -j ACCEPT",
                port->ifname, port->storm_pps_limit);
            fx_run(cmd);
            snprintf(cmd, sizeof(cmd),
                "iptables -A FORWARD -i %s -m pkttype --pkt-type broadcast -j DROP",
                port->ifname);
            fx_run(cmd);
        }
    }

    /* Install the zone matrix into a dedicated FORWARD chain */
    printf("[%s] Installing zone forwarding matrix...\n", BRAND_PRODUCT);
    fx_try("iptables -N FIREX_FWD 2>/dev/null");
    fx_run("iptables -F FIREX_FWD");
    fx_try("iptables -D FORWARD -j FIREX_FWD 2>/dev/null");
    fx_run("iptables -I FORWARD -j FIREX_FWD");

    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *sv = &v->vlans[i];
        if (!sv->enabled) continue;

        for (int j = 0; j < v->vlan_count; j++) {
            vlan_config_t *dv = &v->vlans[j];
            if (!dv->enabled || i == j) continue;

            ivr_action_t act = v->zone_matrix[sv->zone][dv->zone];
            const char *target = (act == IVR_DENY || act == IVR_LOG_DENY)
                                 ? "DROP" : "ACCEPT";

            for (int p = 0; p < v->port_count; p++) {
                if (v->ports[p].mode != PORT_MODE_TRUNK) continue;
                if (!fx_ifname_safe2(v->ports[p].ifname)) continue;
                snprintf(cmd, sizeof(cmd),
                    "iptables -A FIREX_FWD -i %s.%u -o %s.%u -j %s 2>/dev/null",
                    v->ports[p].ifname, sv->vlan_id,
                    v->ports[p].ifname, dv->vlan_id, target);
                fx_run(cmd);
            }
        }

        /* Internet access control per VLAN */
        if (!sv->internet_access) {
            for (int p = 0; p < v->port_count; p++) {
                if (v->ports[p].zone != ZONE_WAN) continue;
                if (!fx_ifname_safe2(v->ports[p].ifname)) continue;
                for (int q = 0; q < v->port_count; q++) {
                    if (v->ports[q].mode != PORT_MODE_TRUNK) continue;
                    if (!fx_ifname_safe2(v->ports[q].ifname)) continue;
                    snprintf(cmd, sizeof(cmd),
                        "iptables -I FIREX_FWD -i %s.%u -o %s -j DROP 2>/dev/null",
                        v->ports[q].ifname, sv->vlan_id, v->ports[p].ifname);
                    fx_run(cmd);
                }
            }
            printf("  [VLAN %4u] %-12s INTERNET BLOCKED\n", sv->vlan_id, sv->name);
        }
    }

    printf("[%s] VLAN provisioning complete: %d VLANs, %d ports.\n",
           BRAND_PRODUCT, v->vlan_count, v->port_count);
    return 0;
}

int vlan_teardown_system(vlan_ctx_t *v) {
    char cmd[256];
    fx_try("iptables -D FORWARD -j FIREX_FWD 2>/dev/null");
    fx_try("iptables -F FIREX_FWD 2>/dev/null");
    fx_try("iptables -X FIREX_FWD 2>/dev/null");

    for (int p = 0; p < v->port_count; p++) {
        if (!fx_ifname_safe2(v->ports[p].ifname)) continue;
        for (int i = 0; i < v->ports[p].allowed_count; i++) {
            snprintf(cmd, sizeof(cmd), "ip link del %s.%u 2>/dev/null",
                     v->ports[p].ifname, v->ports[p].allowed_vlans[i]);
            fx_run(cmd);
        }
    }
    return 0;
}

void vlan_shutdown(vlan_ctx_t *v) {
    pthread_mutex_destroy(&v->lock);
}
