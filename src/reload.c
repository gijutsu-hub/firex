/*
 * Validate / stage / apply / rollback for the enterprise configuration.
 * See include/reload.h for the contract.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "reload.h"
#include "enterprise.h"
#include "inspect.h"
#include "policy.h"
#include "vpn.h"
#include "histstats.h"
#include "shaper.h"
#include "portal.h"
#include "ha.h"
#include "ids.h"
#include "feeds.h"
#include "response.h"
#include "netutil.h"
#include "shellcmd.h"
#include "brand.h"

#define ERR(out, ...) do { \
        snprintf((out)->error, CFG_ERR_LEN, __VA_ARGS__); \
        return -1; } while (0)

#define WARN(out, ...) do { \
        (out)->warnings++; \
        if (!(out)->warning[0]) snprintf((out)->warning, CFG_ERR_LEN, __VA_ARGS__); \
    } while (0)

/* A netmask has to be a run of ones followed by a run of zeroes. */
static bool mask_contiguous(uint32_t mask_net) {
    uint32_t h   = ntohl(mask_net);
    uint32_t inv = ~h;
    return (inv & (inv + 1)) == 0;
}

static bool in_subnet(uint32_t addr, uint32_t subnet, uint32_t mask) {
    return (addr & mask) == (subnet & mask);
}

/* Two CIDR blocks overlap when the shorter prefix contains the other. */
static bool subnets_overlap(uint32_t a, uint32_t am, uint32_t b, uint32_t bm) {
    uint32_t common = (ntohl(am) < ntohl(bm)) ? am : bm;
    return (a & common) == (b & common);
}

int firex_validate(vlan_ctx_t *v, netconf_ctx_t *n, blockpage_ctx_t *bp,
                   vpn_ctx_t *vpn, cfg_validate_t *out) {
    memset(out, 0, sizeof(*out));
    out->vlans    = v->vlan_count;
    out->ports    = v->port_count;
    out->acls     = v->ivr_count;
    out->wans     = n->wan_count;
    out->forwards = n->forward_count;
    out->routes   = n->route_count;
    if (vpn) {
        out->wg_ifaces     = vpn->wg_count;
        out->wg_peers      = vpn->peer_count;
        out->ipsec_tunnels = vpn->tunnel_count;
    }
    if (v->policy) {
        out->aliases   = v->policy->alias_count;
        out->schedules = v->policy->schedule_count;
    }

    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];

    /* ── VLANs ── */
    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *c = &v->vlans[i];

        if (c->vlan_id < 1 || c->vlan_id > 4094)
            ERR(out, "VLAN %u: id must be 1-4094", c->vlan_id);

        for (int j = 0; j < i; j++)
            if (v->vlans[j].vlan_id == c->vlan_id)
                ERR(out, "VLAN %u declared twice", c->vlan_id);

        if (!c->name[0])
            ERR(out, "VLAN %u: name is required", c->vlan_id);

        if (c->zone < 0 || c->zone >= ZONE_MAX)
            ERR(out, "VLAN %u (%s): zone out of range", c->vlan_id, c->name);

        /* A VLAN with no L3 config is legal -- it is a pure L2 segment. But a
         * half-configured one is always a mistake. */
        if (c->subnet || c->netmask || c->gateway) {
            if (!c->netmask)
                ERR(out, "VLAN %u (%s): netmask is required with a subnet",
                    c->vlan_id, c->name);
            if (!mask_contiguous(c->netmask))
                ERR(out, "VLAN %u (%s): netmask %s is not contiguous",
                    c->vlan_id, c->name, fx_ip_str(c->netmask, a, sizeof(a)));
            if (!c->subnet)
                ERR(out, "VLAN %u (%s): subnet is required with a netmask",
                    c->vlan_id, c->name);
            if ((c->subnet & c->netmask) != c->subnet)
                ERR(out, "VLAN %u (%s): %s has host bits set for /%d",
                    c->vlan_id, c->name, fx_ip_str(c->subnet, a, sizeof(a)),
                    fx_netmask_to_cidr(c->netmask));
            if (!c->gateway)
                ERR(out, "VLAN %u (%s): gateway is required with a subnet",
                    c->vlan_id, c->name);
            if (!in_subnet(c->gateway, c->subnet, c->netmask))
                ERR(out, "VLAN %u (%s): gateway %s is outside %s/%d",
                    c->vlan_id, c->name,
                    fx_ip_str(c->gateway, a, sizeof(a)),
                    fx_ip_str(c->subnet,  b, sizeof(b)),
                    fx_netmask_to_cidr(c->netmask));

            for (int j = 0; j < i; j++) {
                vlan_config_t *o = &v->vlans[j];
                if (!o->subnet || !o->netmask) continue;
                if (subnets_overlap(c->subnet, c->netmask, o->subnet, o->netmask))
                    ERR(out, "VLAN %u (%s) subnet %s/%d overlaps VLAN %u (%s)",
                        c->vlan_id, c->name,
                        fx_ip_str(c->subnet, a, sizeof(a)),
                        fx_netmask_to_cidr(c->netmask), o->vlan_id, o->name);
            }
        }

        if (c->dhcp_enabled) {
            if (!c->subnet)
                ERR(out, "VLAN %u (%s): DHCP needs a subnet", c->vlan_id, c->name);
            if (!c->dhcp_start || !c->dhcp_end)
                ERR(out, "VLAN %u (%s): DHCP needs both dhcp_start and dhcp_end",
                    c->vlan_id, c->name);
            if (ntohl(c->dhcp_start) > ntohl(c->dhcp_end))
                ERR(out, "VLAN %u (%s): dhcp_start is above dhcp_end",
                    c->vlan_id, c->name);
            if (!in_subnet(c->dhcp_start, c->subnet, c->netmask) ||
                !in_subnet(c->dhcp_end,   c->subnet, c->netmask))
                ERR(out, "VLAN %u (%s): DHCP pool falls outside %s/%d",
                    c->vlan_id, c->name,
                    fx_ip_str(c->subnet, a, sizeof(a)),
                    fx_netmask_to_cidr(c->netmask));
            if (c->gateway &&
                ntohl(c->gateway) >= ntohl(c->dhcp_start) &&
                ntohl(c->gateway) <= ntohl(c->dhcp_end))
                ERR(out, "VLAN %u (%s): gateway %s sits inside its own DHCP pool",
                    c->vlan_id, c->name, fx_ip_str(c->gateway, a, sizeof(a)));
            if (c->lease_time < 60)
                ERR(out, "VLAN %u (%s): lease_time %d is below 60s",
                    c->vlan_id, c->name, c->lease_time);
        }

        if (c->priority > 7)
            ERR(out, "VLAN %u (%s): 802.1p priority %u is above 7",
                c->vlan_id, c->name, c->priority);
    }

    /* ── Ports ── */
    for (int i = 0; i < v->port_count; i++) {
        port_config_t *p = &v->ports[i];

        if (!p->ifname[0])
            ERR(out, "port %d: interface name is required", i);
        if (!fx_ifname_safe(p->ifname, IFNAME_LEN))
            ERR(out, "port '%s': not a usable interface name", p->ifname);

        for (int j = 0; j < i; j++)
            if (!strcmp(v->ports[j].ifname, p->ifname))
                ERR(out, "port '%s' configured twice", p->ifname);

        if (p->zone < 0 || p->zone >= ZONE_MAX)
            ERR(out, "port '%s': zone out of range", p->ifname);

        if ((p->mode == PORT_MODE_ACCESS || p->mode == PORT_MODE_HYBRID) &&
            p->pvid && p->zone != ZONE_WAN && !vlan_get(v, p->pvid))
            ERR(out, "port '%s': pvid %u has no VLAN definition",
                p->ifname, p->pvid);

        for (int j = 0; j < p->allowed_count; j++)
            if (!vlan_get(v, p->allowed_vlans[j]))
                ERR(out, "port '%s': allowed VLAN %u is not defined",
                    p->ifname, p->allowed_vlans[j]);

        if (p->mode == PORT_MODE_TRUNK && p->allowed_count == 0)
            WARN(out, "port '%s' is a trunk with no allowed VLANs", p->ifname);
    }

    /* ── Aliases and schedules ── */
    policy_ctx_t *pol = v->policy;

    for (int i = 0; pol && i < pol->alias_count; i++) {
        alias_t *al = &pol->aliases[i];
        if (!al->name[0])
            ERR(out, "alias %d: name is required", i);
        if (al->count <= 0)
            ERR(out, "alias '%s': has no entries", al->name);
        for (int j = 0; j < i; j++)
            if (!strcmp(pol->aliases[j].name, al->name))
                ERR(out, "alias '%s' declared twice", al->name);
    }

    for (int i = 0; pol && i < pol->schedule_count; i++) {
        schedule_t *sc = &pol->schedules[i];
        if (!sc->name[0])
            ERR(out, "schedule %d: name is required", i);
        if (!sc->days)
            ERR(out, "schedule '%s': no days selected", sc->name);
        if (sc->start_min < 0 || sc->start_min > 1439 ||
            sc->end_min   < 0 || sc->end_min   > 1439)
            ERR(out, "schedule '%s': times must fall inside a day", sc->name);
        for (int j = 0; j < i; j++)
            if (!strcmp(pol->schedules[j].name, sc->name))
                ERR(out, "schedule '%s' declared twice", sc->name);
    }

    /* ── ACL references ──
     * A rule pointing at an alias that does not exist matches nothing, which
     * reads on the page as though it were active. That is worth refusing. */
    for (int i = 0; i < v->ivr_count; i++) {
        ivr_rule_t *r = &v->ivr[i];
        if (!r->enabled) continue;

        /* Parameters are underscored because the unprefixed names collide
         * with the struct members they are compared against. */
        #define NEED_ALIAS(_field, _want, _what) do { \
            if (r->_field[0]) { \
                if (!pol) \
                    ERR(out, "ACL %d references %s '%s' but no aliases are " \
                        "defined", r->id, _what, r->_field); \
                alias_t *_a = NULL; \
                for (int _j = 0; _j < pol->alias_count; _j++) \
                    if (!strcmp(pol->aliases[_j].name, r->_field)) { \
                        _a = &pol->aliases[_j]; break; } \
                if (!_a) \
                    ERR(out, "ACL %d references undefined %s '$%s'", \
                        r->id, _what, r->_field); \
                if (_a->kind != (_want)) \
                    ERR(out, "ACL %d uses %s alias '$%s' as a %s", \
                        r->id, policy_alias_kind_str(_a->kind), r->_field, _what); \
            } } while (0)

        NEED_ALIAS(src_alias,  ALIAS_NETWORK, "source alias");
        NEED_ALIAS(dst_alias,  ALIAS_NETWORK, "destination alias");
        NEED_ALIAS(port_alias, ALIAS_PORT,    "port alias");
        #undef NEED_ALIAS

        if (r->schedule[0]) {
            bool found = false;
            for (int j = 0; pol && j < pol->schedule_count; j++)
                if (!strcmp(pol->schedules[j].name, r->schedule)) { found = true; break; }
            if (!found)
                ERR(out, "ACL %d references undefined schedule '%s'",
                    r->id, r->schedule);
        }
    }

    /* ── Static routes ── */
    for (int i = 0; i < n->route_count; i++) {
        static_route_t *r = &n->routes[i];
        if (!r->enabled) continue;

        if (!r->gateway)
            ERR(out, "route %d: a gateway is required", i);
        if (r->mask && !mask_contiguous(r->mask))
            ERR(out, "route %d: netmask is not contiguous", i);
        if (r->dest && (r->dest & r->mask) != r->dest)
            ERR(out, "route %d: %s has host bits set for /%d", i,
                fx_ip_str(r->dest, a, sizeof(a)), fx_netmask_to_cidr(r->mask));
        if (r->ifname[0] && !fx_ifname_safe(r->ifname, IFNAME_LEN))
            ERR(out, "route %d: '%s' is not a usable interface name",
                i, r->ifname);
        if (r->metric < 0 || r->metric > 1000000)
            ERR(out, "route %d: metric %d is out of range", i, r->metric);

        /* A default route here would silently fight the WAN and the failover
         * logic for the same slot. */
        if (!r->dest && !r->mask)
            ERR(out, "route %d: use a WAN link for the default route, not a "
                "static route", i);
    }

    /* ── Gateway monitor ── */
    if (n->monitor_interval && (n->monitor_interval < 1 || n->monitor_interval > 3600))
        ERR(out, "monitor: interval %d is outside 1-3600s", n->monitor_interval);
    if (n->monitor_timeout_ms &&
        (n->monitor_timeout_ms < 50 || n->monitor_timeout_ms > 60000))
        ERR(out, "monitor: timeout %dms is outside 50-60000", n->monitor_timeout_ms);
    if (n->monitor_fail && (n->monitor_fail < 1 || n->monitor_fail > 100))
        ERR(out, "monitor: fail_threshold %d is outside 1-100", n->monitor_fail);
    if (n->monitor_ok && (n->monitor_ok < 1 || n->monitor_ok > 100))
        ERR(out, "monitor: ok_threshold %d is outside 1-100", n->monitor_ok);

    if (n->monitor_interval && n->monitor_timeout_ms &&
        n->monitor_timeout_ms > n->monitor_interval * 1000)
        ERR(out, "monitor: a %dms timeout cannot fit in a %ds interval",
            n->monitor_timeout_ms, n->monitor_interval);

    /* ── WAN ── */
    for (int i = 0; i < n->wan_count; i++) {
        wan_config_t *w = &n->wan[i];

        if (!w->ifname[0])
            ERR(out, "wan%d: interface is required", i);
        if (!fx_ifname_safe(w->ifname, IFNAME_LEN))
            ERR(out, "wan%d: '%s' is not a usable interface name", i, w->ifname);

        if (w->mode == WAN_STATIC) {
            if (!w->ip || !w->netmask)
                ERR(out, "wan%d (%s): static mode needs ip and netmask",
                    i, w->ifname);
            if (!mask_contiguous(w->netmask))
                ERR(out, "wan%d (%s): netmask is not contiguous", i, w->ifname);
            if (w->gateway && !in_subnet(w->gateway, w->ip, w->netmask))
                ERR(out, "wan%d (%s): gateway %s is outside the interface subnet",
                    i, w->ifname, fx_ip_str(w->gateway, a, sizeof(a)));
        }
        if (w->mode == WAN_PPPOE && !w->pppoe_user[0])
            ERR(out, "wan%d (%s): pppoe mode needs pppoe_user", i, w->ifname);

        if (w->mtu < 576 || w->mtu > 9216)
            ERR(out, "wan%d (%s): mtu %d is outside 576-9216", i, w->ifname, w->mtu);

        if (w->monitor_ip[0]) {
            struct in_addr probe;
            if (inet_pton(AF_INET, w->monitor_ip, &probe) != 1)
                ERR(out, "wan%d (%s): monitor_ip '%s' is not an IPv4 address",
                    i, w->ifname, w->monitor_ip);
        } else if (n->wan_count > 1) {
            WARN(out, "wan%d (%s) has no monitor_ip, so failover cannot tell "
                 "whether it is up", i, w->ifname);
        }

        for (int j = 0; j < i; j++)
            if (!strcmp(n->wan[j].ifname, w->ifname))
                ERR(out, "wan%d: interface '%s' is already used by wan%d",
                    i, w->ifname, j);
    }

    if (n->wan_count > 1) {
        bool distinct = false;
        for (int i = 1; i < n->wan_count; i++)
            if (n->wan[i].failover_priority != n->wan[0].failover_priority)
                distinct = true;
        if (!distinct)
            WARN(out, "every WAN link has the same failover priority; which "
                 "one wins is then arbitrary");
    }

    /* ── Published services ── */
    for (int i = 0; i < n->forward_count; i++) {
        port_forward_t *f = &n->forwards[i];
        if (!f->enabled) continue;

        if (!f->internal_ip)
            ERR(out, "forward '%s': internal address is required", f->name);
        if (!f->wan_port_start || !f->internal_port)
            ERR(out, "forward '%s': wan port and internal port are required", f->name);
        if (f->protocol != 6 && f->protocol != 17)
            ERR(out, "forward '%s': protocol must be tcp or udp", f->name);

        if (f->dst_vlan && !vlan_get(v, f->dst_vlan))
            ERR(out, "forward '%s': target VLAN %u is not defined",
                f->name, f->dst_vlan);

        for (int j = 0; j < i; j++) {
            port_forward_t *o = &n->forwards[j];
            if (o->enabled && o->protocol == f->protocol &&
                o->wan_port_start == f->wan_port_start)
                ERR(out, "forward '%s': WAN port %u/%s already used by '%s'",
                    f->name, f->wan_port_start,
                    f->protocol == 17 ? "udp" : "tcp", o->name);
        }

        /* A forward into a VLAN that denies inbound inter-VLAN traffic will
         * be DNAT'd and then dropped. Worth saying out loud. */
        vlan_config_t *t = f->dst_vlan ? vlan_get(v, f->dst_vlan) : NULL;
        if (t && !t->inter_vlan_routing)
            WARN(out, "forward '%s' targets VLAN %u, which has inter-VLAN "
                 "routing disabled", f->name, f->dst_vlan);
    }

    /* ── WireGuard ── */
    for (int i = 0; vpn && i < vpn->wg_count; i++) {
        wg_iface_t *w = &vpn->wg[i];
        if (!w->enabled) continue;

        if (!w->ifname[0])
            ERR(out, "wireguard %d: an interface name is required", i);
        if (!fx_ifname_safe(w->ifname, IFNAME_LEN))
            ERR(out, "wireguard '%s': not a usable interface name", w->ifname);
        for (int j = 0; j < i; j++)
            if (!strcmp(vpn->wg[j].ifname, w->ifname))
                ERR(out, "wireguard interface '%s' declared twice", w->ifname);

        if (!w->private_key[0])
            ERR(out, "wireguard '%s': a private key is required", w->ifname);
        if (!wg_key_valid(w->private_key))
            ERR(out, "wireguard '%s': the private key is not a valid 32-byte "
                "base64 key", w->ifname);
        /* listen_port is a uint16_t, so the only value out of range is 0. */
        if (w->listen_port == 0)
            ERR(out, "wireguard '%s': listen_port 0 is not usable", w->ifname);

        /* A published UDP service on the same port would be DNAT'd away
         * before WireGuard ever saw the handshake. */
        for (int j = 0; j < n->forward_count; j++) {
            port_forward_t *fw = &n->forwards[j];
            if (fw->enabled && fw->protocol == 17 &&
                fw->wan_port_start <= w->listen_port &&
                fw->wan_port_end   >= w->listen_port)
                ERR(out, "wireguard '%s': port %u/udp is already forwarded by "
                    "'%s'", w->ifname, w->listen_port, fw->name);
        }
        if (w->mtu < 576 || w->mtu > 9216)
            ERR(out, "wireguard '%s': mtu %d is outside 576-9216",
                w->ifname, w->mtu);
        if (w->zone < 0 || w->zone >= ZONE_MAX)
            ERR(out, "wireguard '%s': zone out of range", w->ifname);

        if (w->address) {
            if (!w->netmask || !mask_contiguous(w->netmask))
                ERR(out, "wireguard '%s': the tunnel netmask is missing or "
                    "not contiguous", w->ifname);
            /* A tunnel address that sits inside a VLAN subnet makes routing
             * ambiguous for every host on that VLAN. */
            for (int j = 0; j < v->vlan_count; j++) {
                vlan_config_t *c = &v->vlans[j];
                if (!c->subnet || !c->netmask) continue;
                if (in_subnet(w->address, c->subnet, c->netmask))
                    ERR(out, "wireguard '%s': address %s is inside VLAN %u "
                        "(%s)", w->ifname,
                        fx_ip_str(w->address, a, sizeof(a)), c->vlan_id, c->name);
            }
        }

        for (int j = 0; j < n->wan_count; j++)
            if (n->wan[j].mode != WAN_DISABLED &&
                !strcmp(n->wan[j].ifname, w->ifname))
                ERR(out, "wireguard '%s': that name is already a WAN link",
                    w->ifname);

        for (int j = 0; j < i; j++)
            if (vpn->wg[j].enabled && vpn->wg[j].listen_port == w->listen_port)
                ERR(out, "wireguard '%s': port %u is already used by '%s'",
                    w->ifname, w->listen_port, vpn->wg[j].ifname);
    }

    /* ── WireGuard peers ── */
    for (int i = 0; vpn && i < vpn->peer_count; i++) {
        wg_peer_t *p = &vpn->peers[i];
        if (!p->enabled) continue;

        if (!p->name[0])
            ERR(out, "wireguard peer %d: a name is required", i);
        for (int j = 0; j < i; j++)
            if (!strcmp(vpn->peers[j].name, p->name))
                ERR(out, "wireguard peer '%s' declared twice", p->name);

        if (!wg_key_valid(p->public_key))
            ERR(out, "peer '%s': the public key is not a valid 32-byte base64 "
                "key", p->name);
        if (p->preshared_key[0] && !wg_key_valid(p->preshared_key))
            ERR(out, "peer '%s': the pre-shared key is malformed", p->name);

        bool on_iface = false;
        for (int j = 0; j < vpn->wg_count; j++)
            if (!strcmp(vpn->wg[j].ifname, p->ifname)) { on_iface = true; break; }
        if (!on_iface)
            ERR(out, "peer '%s': interface '%s' is not configured",
                p->name, p->ifname);

        if (!p->allowed_count)
            ERR(out, "peer '%s': allowed_ips is required, or nothing routes "
                "to it", p->name);

        if (p->zone < 0 || p->zone >= ZONE_MAX)
            ERR(out, "peer '%s': zone out of range", p->name);
        if (p->keepalive < 0 || p->keepalive > 65535)
            ERR(out, "peer '%s': keepalive %d is out of range",
                p->name, p->keepalive);

        for (int k = 0; k < p->allowed_count; k++) {
            uint32_t ip4 = p->allowed[k].ip, m = p->allowed[k].mask;
            if (!m && !ip4)
                ERR(out, "peer '%s': an empty allowed_ips entry", p->name);
            if (m && !mask_contiguous(m))
                ERR(out, "peer '%s': allowed_ips netmask is not contiguous",
                    p->name);

            /* Two peers claiming the same address makes which one receives
             * it a matter of ordering. */
            for (int j = 0; j < i; j++) {
                wg_peer_t *o = &vpn->peers[j];
                if (!o->enabled || strcmp(o->ifname, p->ifname)) continue;
                for (int q = 0; q < o->allowed_count; q++)
                    if (o->allowed[q].ip == ip4 && o->allowed[q].mask == m)
                        ERR(out, "peer '%s' claims %s, which peer '%s' already "
                            "claims", p->name,
                            fx_ip_str(ip4, a, sizeof(a)), o->name);
            }
        }

        /* A site-to-site peer needs somewhere to send the handshake; a
         * roaming one does not, but then it cannot be dialled out to. */
        if (!p->endpoint_host[0] && p->keepalive > 0)
            WARN(out, "peer '%s' has a keepalive but no endpoint, so it can "
                 "only ever connect inbound", p->name);
    }

    /* ── IPsec ── */
    for (int i = 0; vpn && i < vpn->tunnel_count; i++) {
        ipsec_tunnel_t *t = &vpn->tunnels[i];
        if (!t->enabled) continue;

        if (!t->name[0])
            ERR(out, "ipsec %d: a name is required", i);
        for (int j = 0; j < i; j++)
            if (!strcmp(vpn->tunnels[j].name, t->name))
                ERR(out, "ipsec tunnel '%s' declared twice", t->name);

        if (!t->remote_host[0])
            ERR(out, "ipsec '%s': remote_host is required", t->name);
        if (!t->psk[0])
            ERR(out, "ipsec '%s': a pre-shared key is required", t->name);
        if (strlen(t->psk) < 16)
            ERR(out, "ipsec '%s': the pre-shared key is under 16 characters",
                t->name);
        if (!t->remote_subnet && !t->remote_mask)
            ERR(out, "ipsec '%s': remote_subnet is required", t->name);
        if (t->local_mask && !mask_contiguous(t->local_mask))
            ERR(out, "ipsec '%s': local_subnet netmask is not contiguous",
                t->name);
        if (t->remote_mask && !mask_contiguous(t->remote_mask))
            ERR(out, "ipsec '%s': remote_subnet netmask is not contiguous",
                t->name);
        if (t->local_subnet && t->remote_subnet &&
            subnets_overlap(t->local_subnet, t->local_mask,
                            t->remote_subnet, t->remote_mask))
            ERR(out, "ipsec '%s': the local and remote subnets overlap",
                t->name);
        if (t->ike_lifetime < 60 || t->ike_lifetime > 86400)
            ERR(out, "ipsec '%s': ike_lifetime %d is outside 60-86400s",
                t->name, t->ike_lifetime);
        if (t->esp_lifetime < 60 || t->esp_lifetime > 86400)
            ERR(out, "ipsec '%s': esp_lifetime %d is outside 60-86400s",
                t->name, t->esp_lifetime);
        if (t->esp_lifetime > t->ike_lifetime)
            WARN(out, "ipsec '%s': the ESP lifetime outlives the IKE SA that "
                 "carries it", t->name);
        if (t->zone < 0 || t->zone >= ZONE_MAX)
            ERR(out, "ipsec '%s': zone out of range", t->name);
        if (t->version == IKE_V1)
            WARN(out, "ipsec '%s' uses IKEv1, which is obsolete; prefer IKEv2",
                 t->name);
    }

    /* ── Shaping ── */
    {
        shaper_cfg_t *sc = &n->shaping;

        if (sc->wan_up_mbps < 0 || sc->wan_up_mbps > 100000)
            ERR(out, "shaping: wan_up_mbps %d is outside 0-100000",
                sc->wan_up_mbps);
        if (sc->wan_down_mbps < 0 || sc->wan_down_mbps > 100000)
            ERR(out, "shaping: wan_down_mbps %d is outside 0-100000",
                sc->wan_down_mbps);
        if (sc->codel_target_ms &&
            (sc->codel_target_ms < 1 || sc->codel_target_ms > 1000))
            ERR(out, "shaping: codel_target_ms %d is outside 1-1000",
                sc->codel_target_ms);
        if (sc->codel_interval_ms &&
            (sc->codel_interval_ms < 1 || sc->codel_interval_ms > 10000))
            ERR(out, "shaping: codel_interval_ms %d is outside 1-10000",
                sc->codel_interval_ms);
        if (sc->codel_target_ms && sc->codel_interval_ms &&
            sc->codel_target_ms >= sc->codel_interval_ms)
            ERR(out, "shaping: the CoDel target must be well below its "
                "interval (%dms target, %dms interval)",
                sc->codel_target_ms, sc->codel_interval_ms);

        if (sc->enabled && sc->ingress_shaping && !sc->wan_down_mbps)
            ERR(out, "shaping: ingress_shaping needs a wan_down_mbps ceiling "
                "to enforce");

        /* A VLAN cannot be promised more than the link can carry. */
        if (sc->enabled && sc->wan_up_mbps > 0)
            for (int i = 0; i < v->vlan_count; i++) {
                vlan_config_t *c = &v->vlans[i];
                if (c->bandwidth_up_mbps > sc->wan_up_mbps)
                    ERR(out, "shaping: VLAN %u (%s) is given %d Mbit up, "
                        "above the %d Mbit WAN ceiling", c->vlan_id, c->name,
                        c->bandwidth_up_mbps, sc->wan_up_mbps);
            }

        for (int i = 0; i < v->vlan_count; i++) {
            vlan_config_t *c = &v->vlans[i];
            if (c->bandwidth_up_mbps < 0 || c->bandwidth_down_mbps < 0)
                ERR(out, "VLAN %u (%s): a negative bandwidth limit",
                    c->vlan_id, c->name);
            if (!sc->enabled &&
                (c->bandwidth_up_mbps || c->bandwidth_down_mbps))
                WARN(out, "VLAN %u (%s) has bandwidth limits but shaping is "
                     "disabled, so they do nothing", c->vlan_id, c->name);
        }
    }

    /* ── Captive portal ── */
    {
        portal_cfg_t *pc = &n->portal;

        if (pc->session_minutes &&
            (pc->session_minutes < 1 || pc->session_minutes > 10080))
            ERR(out, "portal: session_minutes %d is outside 1-10080",
                pc->session_minutes);
        if (pc->idle_minutes &&
            (pc->idle_minutes < 1 || pc->idle_minutes > 10080))
            ERR(out, "portal: idle_minutes %d is outside 1-10080",
                pc->idle_minutes);
        if (pc->session_minutes && pc->idle_minutes &&
            pc->idle_minutes > pc->session_minutes)
            WARN(out, "portal: the idle timeout outlives the session, so it "
                 "can never fire");

        if (pc->enabled && pc->auth == PORTAL_AUTH_RADIUS) {
            if (!pc->radius_host[0])
                ERR(out, "portal: RADIUS auth needs radius_host");
            if (!pc->radius_secret[0])
                ERR(out, "portal: RADIUS auth needs a shared secret");
            if (strlen(pc->radius_secret) < 8)
                ERR(out, "portal: the RADIUS shared secret is under 8 "
                    "characters");
        }
        if (pc->radius_timeout_ms &&
            (pc->radius_timeout_ms < 100 || pc->radius_timeout_ms > 30000))
            ERR(out, "portal: radius_timeout_ms %d is outside 100-30000",
                pc->radius_timeout_ms);
        if (pc->radius_retries &&
            (pc->radius_retries < 1 || pc->radius_retries > 10))
            ERR(out, "portal: radius_retries %d is outside 1-10",
                pc->radius_retries);

        if (pc->enabled) {
            int captive = 0;
            for (int i = 0; i < v->vlan_count; i++)
                if (v->vlans[i].enabled && v->vlans[i].captive_portal) {
                    captive++;
                    if (!v->vlans[i].subnet)
                        ERR(out, "VLAN %u (%s) is captive but has no subnet, "
                            "so there is nothing to intercept",
                            v->vlans[i].vlan_id, v->vlans[i].name);
                }
            if (!captive)
                WARN(out, "the portal is enabled but no VLAN has "
                     "captive_portal set, so it will never be reached");
        } else {
            for (int i = 0; i < v->vlan_count; i++)
                if (v->vlans[i].enabled && v->vlans[i].captive_portal)
                    WARN(out, "VLAN %u (%s) is marked captive but the portal "
                         "is disabled, so its clients are not intercepted",
                         v->vlans[i].vlan_id, v->vlans[i].name);
        }
    }

    /* ── High availability ── */
    {
        ha_cfg_t *hc = &n->ha;

        if (hc->vrrp_id && (hc->vrrp_id < 1 || hc->vrrp_id > 255))
            ERR(out, "ha: vrrp_id %d is outside 1-255", hc->vrrp_id);
        if (hc->priority && (hc->priority < 1 || hc->priority > 254))
            ERR(out, "ha: priority %d is outside 1-254", hc->priority);
        if (hc->advert_interval &&
            (hc->advert_interval < 1 || hc->advert_interval > 255))
            ERR(out, "ha: advert_interval %d is outside 1-255s",
                hc->advert_interval);

        if (!hc->enabled) {
            /* nothing further to check */
        } else {
            if (!hc->peer_address[0])
                ERR(out, "ha: a peer_address is required");
            if (!hc->sync_interface[0])
                ERR(out, "ha: a sync_interface is required");
            if (!fx_ifname_safe(hc->sync_interface, IFNAME_LEN))
                ERR(out, "ha: sync_interface '%s' is not a usable name",
                    hc->sync_interface);

            struct in_addr pa, sa;
            if (inet_pton(AF_INET, hc->peer_address, &pa) != 1)
                ERR(out, "ha: peer_address '%s' is not an IPv4 address",
                    hc->peer_address);
            if (hc->sync_address[0] &&
                inet_pton(AF_INET, hc->sync_address, &sa) != 1)
                ERR(out, "ha: sync_address '%s' is not an IPv4 address",
                    hc->sync_address);

            if (hc->sync_address[0] &&
                !strcmp(hc->sync_address, hc->peer_address))
                ERR(out, "ha: this node and its peer cannot share one address");

            /*
             * A gateway that is also a node's own sync address would mean
             * VRRP moving an address the node needs to keep in order to talk
             * to its peer.
             */
            if (hc->sync_address[0])
                for (int i = 0; i < v->vlan_count; i++)
                    if (v->vlans[i].gateway == sa.s_addr)
                        ERR(out, "ha: sync_address %s is VLAN %u's gateway, "
                            "which VRRP will move", hc->sync_address,
                            v->vlans[i].vlan_id);

            if (hc->conntrack_sync) {
                if (hc->conntrack_port < 1 || hc->conntrack_port > 65535)
                    ERR(out, "ha: conntrack_port %d is out of range",
                        hc->conntrack_port);
                if (hc->conntrack_port == bp->port)
                    ERR(out, "ha: conntrack_port %d collides with the portal",
                        hc->conntrack_port);
            }

            if (hc->config_sync) {
                if (!hc->sync_secret[0])
                    ERR(out, "ha: config_sync needs a sync_secret; the push "
                        "is authenticated by it and nothing else");
                if (strlen(hc->sync_secret) < 16)
                    ERR(out, "ha: the sync_secret is under 16 characters");
                if (hc->config_sync_port < 1 || hc->config_sync_port > 65535)
                    ERR(out, "ha: config_sync_port %d is out of range",
                        hc->config_sync_port);
            }

            /* Both nodes must agree, and only one can win by priority. */
            if (hc->role == HA_ROLE_PRIMARY && hc->priority &&
                hc->priority <= 100)
                WARN(out, "ha: the primary's priority (%d) is not above the "
                     "secondary default of 100, so which node wins is "
                     "arbitrary", hc->priority);

            if (!hc->vrrp_password[0])
                WARN(out, "ha: no vrrp_password is set, so any host on the "
                     "sync link can claim the virtual addresses");
            else if (strlen(hc->vrrp_password) > 8)
                WARN(out, "ha: VRRPv2 only uses the first 8 characters of "
                     "vrrp_password; the rest is ignored");

            int vips = 0;
            for (int i = 0; i < v->vlan_count; i++)
                if (v->vlans[i].enabled && v->vlans[i].gateway) vips++;
            if (!vips)
                WARN(out, "ha is enabled but no VLAN has a gateway, so there "
                     "is nothing for VRRP to move");
        }
    }

    /* ── Threat layer ── */
    {
        threat_cfg_t *tc = &n->threat;

        if (tc->enabled && !tc->rules_path[0] && !n->feed_count)
            WARN(out, "the threat layer is enabled but has neither a rules "
                 "file nor a feed, so it has nothing to match on");

        /*
         * A missing rules file is loud but not fatal: the appliance should
         * still come up with the rest of its configuration rather than
         * refusing to boot because a ruleset has not been installed yet.
         * Bounded so a long path truncates the path, not the sentence.
         */
        if (tc->enabled && tc->rules_path[0] &&
            access(tc->rules_path, R_OK) != 0)
            WARN(out, "threat: cannot read the rules file %.180s; no "
                 "signatures will load", tc->rules_path);

        /*
         * A rule that says drop only drops in inline mode. Saying so is
         * worth a warning: "enabled but not inline" is the safe way to
         * deploy a ruleset and also an easy thing to forget about.
         */
        if (tc->enabled && !tc->inline_mode)
            WARN(out, "the threat layer is in alert-only mode, so drop rules "
                 "will report and let traffic through");

        int ips_vlans = 0;
        for (int i = 0; i < v->vlan_count; i++)
            if (v->vlans[i].enabled &&
                (v->vlans[i].ips_enabled || v->vlans[i].malware_scan))
                ips_vlans++;

        if (tc->enabled && !ips_vlans)
            WARN(out, "no VLAN has ips or malware_scan set, so no traffic "
                 "reaches the signature engine");
        if (!tc->enabled && ips_vlans)
            WARN(out, "%d VLAN(s) ask for inspection but the threat layer is "
                 "disabled", ips_vlans);

        for (int i = 0; i < n->feed_count; i++) {
            feed_t *fd = &n->feeds[i];
            if (!fd->name[0])
                ERR(out, "feed %d: a name is required", i);
            if (!fd->url[0])
                ERR(out, "feed '%s': a url is required", fd->name);
            if (strncmp(fd->url, "http://", 7) &&
                strncmp(fd->url, "https://", 8) &&
                strncmp(fd->url, "file://", 7))
                ERR(out, "feed '%s': the url must be http://, https:// or "
                    "file://", fd->name);
            if (fd->refresh_minutes < 5 || fd->refresh_minutes > 40320)
                ERR(out, "feed '%s': refresh %d is outside 5 minutes to 4 "
                    "weeks", fd->name, fd->refresh_minutes);
            for (int j = 0; j < i; j++)
                if (!strcmp(n->feeds[j].name, fd->name))
                    ERR(out, "feed '%s' declared twice", fd->name);

            /* An http:// list can be rewritten by anyone on the path, and a
             * blocklist an attacker chooses is worse than none. */
            if (!strncmp(fd->url, "http://", 7))
                WARN(out, "feed '%s' is fetched over plain HTTP, so its "
                     "contents can be altered in transit", fd->name);
        }
    }

    /* ── Automatic response ── */
    {
        response_cfg_t *rc = &n->response;

        if (rc->threshold && (rc->threshold < 1 || rc->threshold > 1000))
            ERR(out, "response: threshold %d is outside 1-1000", rc->threshold);
        if (rc->block_minutes && (rc->block_minutes < 1 || rc->block_minutes > 43200))
            ERR(out, "response: block_minutes %d is outside 1-43200",
                rc->block_minutes);
        if (rc->max_block_minutes &&
            (rc->max_block_minutes < 1 || rc->max_block_minutes > 43200))
            ERR(out, "response: max_block_minutes %d is outside 1-43200",
                rc->max_block_minutes);
        if (rc->block_minutes && rc->max_block_minutes &&
            rc->max_block_minutes < rc->block_minutes)
            ERR(out, "response: max_block_minutes is below block_minutes, so "
                "escalation would shorten a block");
        if (rc->decay_minutes && (rc->decay_minutes < 1 || rc->decay_minutes > 43200))
            ERR(out, "response: decay_minutes %d is outside 1-43200",
                rc->decay_minutes);

        if (rc->enabled && !n->threat.enabled)
            WARN(out, "automatic response is on but the threat layer is off, "
                 "so nothing will ever trigger it");

        /*
         * Quarantine moves a host into ZONE_QUARANTINE. If that row permits
         * everything, quarantine is a no-op dressed as an action.
         */
        if (rc->enabled && rc->quarantine) {
            bool any_deny = false;
            for (int z = 0; z < ZONE_MAX; z++)
                if (z != ZONE_QUARANTINE &&
                    (v->zone_matrix[ZONE_QUARANTINE][z] == IVR_DENY ||
                     v->zone_matrix[ZONE_QUARANTINE][z] == IVR_LOG_DENY)) {
                    any_deny = true;
                    break;
                }
            if (!any_deny)
                WARN(out, "quarantine is on but the QUARANTINE zone is not "
                     "denied anywhere in the matrix, so quarantining a host "
                     "would change nothing");
        }
    }

    /* ── Telemetry ── */
    {
        telemetry_cfg_t *tc = &n->telemetry;

        if (tc->syslog_facility &&
            (tc->syslog_facility < 0 || tc->syslog_facility > 23))
            ERR(out, "telemetry: syslog_facility %d is outside 0-23",
                tc->syslog_facility);
        if (tc->syslog_min_severity &&
            (tc->syslog_min_severity < 0 || tc->syslog_min_severity > 7))
            ERR(out, "telemetry: syslog_min_severity %d is outside 0-7",
                tc->syslog_min_severity);
        if (tc->netflow_interval &&
            (tc->netflow_interval < 5 || tc->netflow_interval > 3600))
            ERR(out, "telemetry: netflow_interval %d is outside 5-3600s",
                tc->netflow_interval);
        if (tc->history_interval &&
            (tc->history_interval < HIST_MIN_INTERVAL ||
             tc->history_interval > HIST_MAX_INTERVAL))
            ERR(out, "telemetry: history_interval %d is outside %d-%ds",
                tc->history_interval, HIST_MIN_INTERVAL, HIST_MAX_INTERVAL);

        /* Shipping logs to an address the box itself serves would loop. */
        if (tc->syslog_host[0]) {
            struct in_addr sa;
            if (inet_pton(AF_INET, tc->syslog_host, &sa) == 1)
                for (int i = 0; i < v->vlan_count; i++)
                    if (v->vlans[i].gateway == sa.s_addr)
                        ERR(out, "telemetry: syslog_host %s is this "
                            "appliance's own gateway on VLAN %u",
                            tc->syslog_host, v->vlans[i].vlan_id);
        }
        if (tc->netflow_port && tc->netflow_port == bp->port)
            ERR(out, "telemetry: netflow_port %u collides with the portal",
                tc->netflow_port);
    }

    /* ── Portal ── */
    if (bp->enabled) {
        int port = bp->port ? bp->port : BLOCKPAGE_PORT;
        if (port < 1 || port > 65535)
            ERR(out, "blockpage: port %d is out of range", port);
        if (port < 1024)
            WARN(out, "blockpage: port %d needs root to bind", port);
    }

    /* ── Console listener ── */
    {
        int cport = n->console_port ? n->console_port : CONSOLE_PORT;
        int pport = bp->port ? bp->port : BLOCKPAGE_PORT;

        if (cport < 1 || cport > 65535)
            ERR(out, "console: port %d is out of range", cport);

        /*
         * The console and the block page are two listeners with opposite
         * exposure: the portal has to face the segments being defended
         * against, the console must not. Same port and no narrowing bind
         * means one socket again, which is the exposure the split exists
         * to remove -- so it is an error, not a warning.
         */
        if (cport == pport) {
            bool narrowed = n->console_bind[0] &&
                            strcasecmp(n->console_bind, "any") != 0 &&
                            strcasecmp(n->console_bind, "mgmt") != 0;
            if (!narrowed)
                ERR(out, "console: port %d is the block page's port, so the "
                         "admin console would be reachable from every segment "
                         "the portal faces", cport);
        }

        if (n->console_bind[0] && strcasecmp(n->console_bind, "any") &&
            strcasecmp(n->console_bind, "mgmt")) {
            struct in_addr in;
            if (inet_pton(AF_INET, n->console_bind, &in) != 1)
                ERR(out, "console: bind '%s' is not an address, \"mgmt\" or "
                         "\"any\"", n->console_bind);
        }
        if (!strcasecmp(n->console_bind, "any"))
            WARN(out, "console: bound to every interface; an appliance with a "
                      "management zone should name it instead");
    }

    /* ── Air gap ── */
    {
        ag_cfg_t *ac = &n->airgap;

        /*
         * manual + scheduled + require_time_sync is a deadlock, and a
         * quiet one. `manual` means the appliance fetches nothing of its
         * own -- including NTP -- so the clock never becomes disciplined;
         * `require_time_sync` then fails the schedule shut; and the gap
         * that was supposed to open every night never opens at all.
         * Nobody finds out until a site has been cut off for a week.
         *
         * The two features cancel out, so the configuration is refused
         * with the three ways out spelled in the message rather than
         * being accepted and silently doing nothing.
         */
        if (ac->mode == AG_MANUAL && n->airgap_window_count > 0 &&
            ac->require_time_sync)
            ERR(out, "airgap: mode 'manual' fetches no time of its own, so "
                     "require_time_sync can never be satisfied and every "
                     "window stays shut -- use mode 'scheduled', set "
                     "require_time_sync = no, or drop the windows");

        if (ac->mode == AG_SCHEDULED && n->airgap_window_count == 0)
            WARN(out, "airgap: mode is 'scheduled' with no windows, so the "
                      "gap never opens");

        for (int i = 0; i < n->airgap_window_count; i++) {
            ag_window_t *w = &n->airgap_windows[i];
            if (!w->used) continue;
            if (w->start_min >= 1440 || w->end_min > 1440)
                ERR(out, "airgap window '%s': times must be inside a day",
                    w->name);
            if (w->start_min == w->end_min)
                ERR(out, "airgap window '%s': start and end are the same, so "
                         "it never opens", w->name);
            if (!w->days)
                ERR(out, "airgap window '%s': no days selected", w->name);
            if (!w->allow_in && !w->allow_out)
                WARN(out, "airgap window '%s' permits neither direction",
                     w->name);
        }
    }

    /* ── Malware ── */
    {
        mw_cfg_t *mc = &n->malware;
        if (mc->enabled) {
            if (mc->max_object_kb < 0)
                ERR(out, "malware: max_object_kb cannot be negative");
            /* The path is up to 255 bytes and the message buffer is
             * smaller, so it is bounded explicitly rather than relying on
             * snprintf to cut it somewhere arbitrary. */
            if (mc->db_path[0] && access(mc->db_path, R_OK) != 0)
                WARN(out, "malware: cannot read %.120s; only the built-in "
                          "byte patterns will run", mc->db_path);
        }
    }

    return 0;
}

int firex_validate_file(const char *path, cfg_validate_t *out) {
    memset(out, 0, sizeof(*out));

    vlan_ctx_t      *sv = calloc(1, sizeof(*sv));
    netconf_ctx_t   *sn = calloc(1, sizeof(*sn));
    blockpage_ctx_t *sb = calloc(1, sizeof(*sb));
    policy_ctx_t    *sp = calloc(1, sizeof(*sp));
    vpn_ctx_t       *sx = calloc(1, sizeof(*sx));
    if (!sv || !sn || !sb || !sp || !sx) {
        free(sv); free(sn); free(sb); free(sp); free(sx);
        snprintf(out->error, CFG_ERR_LEN, "out of memory");
        return -1;
    }

    vlan_init(sv);
    netconf_init(sn);
    policy_init(sp);
    vpn_init(sx);
    vlan_set_policy(sv, sp);
    sb->port           = BLOCKPAGE_PORT;
    sb->show_logo      = true;
    sb->show_technical = true;
    sb->allow_override = true;

    int rc;
    if (firex_load_enterprise_config_ex(path, sv, sn, sb, sp, sx) != 0) {
        snprintf(out->error, CFG_ERR_LEN, "cannot read %s", path);
        rc = -1;
    } else {
        rc = firex_validate(sv, sn, sb, sx, out);
    }

    vlan_shutdown(sv);
    netconf_shutdown(sn);
    policy_shutdown(sp);
    vpn_shutdown(sx);
    free(sv); free(sn); free(sb); free(sp); free(sx);
    return rc;
}

bool firex_needs_restart(const blockpage_ctx_t *live, const blockpage_ctx_t *cand) {
    int lp = live->port ? live->port : BLOCKPAGE_PORT;
    int cp = cand->port ? cand->port : BLOCKPAGE_PORT;
    return live->enabled != cand->enabled || lp != cp;
}

/* ── Live swap ──────────────────────────────────────────────────────────
 * The live contexts carry a mutex and running counters that must survive a
 * reload; everything else is replaced wholesale. Counters are carried across
 * per VLAN id, so a segment that still exists keeps its history.
 */
static void vlan_adopt(vlan_ctx_t *live, const vlan_ctx_t *stage) {
    vlan_config_t old[MAX_VLANS];
    int old_count = live->vlan_count;
    memcpy(old, live->vlans, sizeof(old));

    memcpy(live->vlans, stage->vlans, sizeof(live->vlans));
    memcpy(live->ports, stage->ports, sizeof(live->ports));
    memcpy(live->ivr,   stage->ivr,   sizeof(live->ivr));
    memcpy(live->zone_matrix, stage->zone_matrix, sizeof(live->zone_matrix));
    live->vlan_count = stage->vlan_count;
    live->port_count = stage->port_count;
    live->ivr_count  = stage->ivr_count;

    for (int i = 0; i < live->vlan_count; i++)
        for (int j = 0; j < old_count; j++)
            if (old[j].vlan_id == live->vlans[i].vlan_id) {
                live->vlans[i].rx_packets     = old[j].rx_packets;
                live->vlans[i].tx_packets     = old[j].tx_packets;
                live->vlans[i].rx_bytes       = old[j].rx_bytes;
                live->vlans[i].tx_bytes       = old[j].tx_bytes;
                live->vlans[i].blocked_packets= old[j].blocked_packets;
                live->vlans[i].active_clients = old[j].active_clients;
                break;
            }
}

static void policy_adopt(policy_ctx_t *live, const policy_ctx_t *stage) {
    /* Hit counters are per-alias and keyed by name, so an alias that survives
     * a reload keeps its history. */
    alias_t old[MAX_ALIASES];
    int old_count = live->alias_count;
    memcpy(old, live->aliases, sizeof(old));

    memcpy(live->aliases,   stage->aliases,   sizeof(live->aliases));
    memcpy(live->schedules, stage->schedules, sizeof(live->schedules));
    live->alias_count    = stage->alias_count;
    live->schedule_count = stage->schedule_count;

    for (int i = 0; i < live->alias_count; i++)
        for (int j = 0; j < old_count; j++)
            if (!strcmp(old[j].name, live->aliases[i].name)) {
                live->aliases[i].hits = old[j].hits;
                break;
            }
}

/* Live byte counters and handshake times belong to the running tunnel, so a
 * peer that survives a reload keeps them. */
static void vpn_adopt(vpn_ctx_t *live, const vpn_ctx_t *stage) {
    wg_peer_t old[MAX_WG_PEERS];
    int old_count = live->peer_count;
    memcpy(old, live->peers, sizeof(old));

    memcpy(live->wg,      stage->wg,      sizeof(live->wg));
    memcpy(live->peers,   stage->peers,   sizeof(live->peers));
    memcpy(live->tunnels, stage->tunnels, sizeof(live->tunnels));
    live->wg_count     = stage->wg_count;
    live->peer_count   = stage->peer_count;
    live->tunnel_count = stage->tunnel_count;

    for (int i = 0; i < live->peer_count; i++)
        for (int j = 0; j < old_count; j++)
            if (!strcmp(old[j].name, live->peers[i].name)) {
                live->peers[i].rx_bytes       = old[j].rx_bytes;
                live->peers[i].tx_bytes       = old[j].tx_bytes;
                live->peers[i].last_handshake = old[j].last_handshake;
                break;
            }
    explicit_bzero(old, sizeof(old));
}

static void netconf_adopt(netconf_ctx_t *live, const netconf_ctx_t *stage) {
    memcpy(live->wan,      stage->wan,      sizeof(live->wan));
    memcpy(live->forwards, stage->forwards, sizeof(live->forwards));
    memcpy(live->routes,   stage->routes,   sizeof(live->routes));
    memcpy(live->reservations, stage->reservations, sizeof(live->reservations));
    live->wan_count         = stage->wan_count;
    live->forward_count     = stage->forward_count;
    live->route_count       = stage->route_count;
    live->reservation_count = stage->reservation_count;
    live->ipv6_enabled      = stage->ipv6_enabled;
    live->hairpin_nat       = stage->hairpin_nat;
    live->telemetry          = stage->telemetry;
    live->shaping            = stage->shaping;
    live->portal             = stage->portal;
    live->ha                 = stage->ha;
    live->threat             = stage->threat;
    live->response           = stage->response;
    memcpy(live->feeds, stage->feeds, sizeof(live->feeds));
    live->feed_count         = stage->feed_count;
    live->monitor_interval   = stage->monitor_interval;
    live->monitor_timeout_ms = stage->monitor_timeout_ms;
    live->monitor_fail       = stage->monitor_fail;
    live->monitor_ok         = stage->monitor_ok;
    memcpy(live->domain, stage->domain, sizeof(live->domain));
}

/* Only the policy fields. The socket, the event ring and the router stay as
 * they are -- a reload must not drop the listener out from under a request. */
static void blockpage_adopt(blockpage_ctx_t *live, const blockpage_ctx_t *stage) {
    memcpy(live->org_name,      stage->org_name,      sizeof(live->org_name));
    memcpy(live->admin_contact, stage->admin_contact, sizeof(live->admin_contact));
    live->show_technical = stage->show_technical;
    live->allow_override = stage->allow_override;
    live->show_logo      = stage->show_logo;
}

static int apply_all(bool apply_net) {
    if (!apply_net) return 0;

    unsigned before = fx_run_failures();

    netconf_apply_wan(&g_netconf);
    vlan_apply_to_system(&g_vlan);
    netconf_apply_nat(&g_netconf, &g_vlan);
    netconf_apply_forwards(&g_netconf);
    netconf_apply_routes(&g_netconf);
    shaper_apply(&g_shaper, &g_vlan, &g_netconf);

    if (g_vpn.wg_count)     vpn_apply_wg(&g_vpn);
    if (g_vpn.tunnel_count) vpn_apply_ipsec(&g_vpn);

    if (netconf_generate_dhcp(&g_netconf, &g_vlan, "/etc/dnsmasq.conf") == 0) {
        fx_try("killall dnsmasq 2>/dev/null");
        fx_try("dnsmasq -C /etc/dnsmasq.conf 2>/dev/null &");
    }

    return (int)(fx_run_failures() - before);
}

int firex_reload_file(const char *path, bool apply_net, char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';

    /* 1. Parse and validate the candidate, well away from anything live. */
    vlan_ctx_t      *sv = calloc(1, sizeof(*sv));
    netconf_ctx_t   *sn = calloc(1, sizeof(*sn));
    blockpage_ctx_t *sb = calloc(1, sizeof(*sb));
    policy_ctx_t    *sp = calloc(1, sizeof(*sp));
    vpn_ctx_t       *sx = calloc(1, sizeof(*sx));
    vlan_ctx_t      *bv = calloc(1, sizeof(*bv));   /* rollback snapshots */
    netconf_ctx_t   *bn = calloc(1, sizeof(*bn));
    policy_ctx_t    *bp2 = calloc(1, sizeof(*bp2));
    vpn_ctx_t       *bx = calloc(1, sizeof(*bx));

    if (!sv || !sn || !sb || !sp || !sx || !bv || !bn || !bp2 || !bx) {
        free(sv); free(sn); free(sb); free(sp); free(sx);
        free(bv); free(bn); free(bp2); free(bx);
        if (err) snprintf(err, errlen, "out of memory");
        return -1;
    }

    int rc = -1;
    vlan_init(sv);
    netconf_init(sn);
    policy_init(sp);
    vpn_init(sx);
    vlan_set_policy(sv, sp);
    sb->port           = g_blockpage.port;
    sb->enabled        = g_blockpage.enabled;
    sb->show_logo      = true;
    sb->show_technical = true;
    sb->allow_override = true;

    if (firex_load_enterprise_config_ex(path, sv, sn, sb, sp, sx) != 0) {
        if (err) snprintf(err, errlen, "cannot read %s", path);
        goto out;
    }

    cfg_validate_t res;
    if (firex_validate(sv, sn, sb, sx, &res) != 0) {
        if (err) snprintf(err, errlen, "%s", res.error);
        goto out;
    }
    if (res.warnings)
        printf("[%s] reload: %d warning(s), first: %s\n",
               BRAND_PRODUCT, res.warnings, res.warning);

    if (firex_needs_restart(&g_blockpage, sb))
        printf("[%s] reload: portal port/enable change takes effect on restart\n",
               BRAND_PRODUCT);

    /* 2. Snapshot the live state so a failed apply can be undone. */
    pthread_mutex_lock(&g_vlan.lock);
    pthread_mutex_lock(&g_netconf.lock);

    memcpy(bv->vlans, g_vlan.vlans, sizeof(bv->vlans));
    memcpy(bv->ports, g_vlan.ports, sizeof(bv->ports));
    memcpy(bv->ivr,   g_vlan.ivr,   sizeof(bv->ivr));
    memcpy(bv->zone_matrix, g_vlan.zone_matrix, sizeof(bv->zone_matrix));
    bv->vlan_count = g_vlan.vlan_count;
    bv->port_count = g_vlan.port_count;
    bv->ivr_count  = g_vlan.ivr_count;
    memcpy(bn, &g_netconf, sizeof(*bn));
    memcpy(bp2->aliases,   g_policy.aliases,   sizeof(bp2->aliases));
    memcpy(bp2->schedules, g_policy.schedules, sizeof(bp2->schedules));
    bp2->alias_count    = g_policy.alias_count;
    bp2->schedule_count = g_policy.schedule_count;

    pthread_mutex_lock(&g_vpn.lock);
    memcpy(bx->wg,      g_vpn.wg,      sizeof(bx->wg));
    memcpy(bx->peers,   g_vpn.peers,   sizeof(bx->peers));
    memcpy(bx->tunnels, g_vpn.tunnels, sizeof(bx->tunnels));
    bx->wg_count     = g_vpn.wg_count;
    bx->peer_count   = g_vpn.peer_count;
    bx->tunnel_count = g_vpn.tunnel_count;
    pthread_mutex_unlock(&g_vpn.lock);

    /* 3. Swap. */
    pthread_mutex_lock(&g_policy.lock);
    policy_adopt(&g_policy, sp);
    pthread_mutex_unlock(&g_policy.lock);

    pthread_mutex_lock(&g_vpn.lock);
    vpn_adopt(&g_vpn, sx);
    pthread_mutex_unlock(&g_vpn.lock);

    vlan_adopt(&g_vlan, sv);
    netconf_adopt(&g_netconf, sn);
    blockpage_adopt(&g_blockpage, sb);

    pthread_mutex_unlock(&g_netconf.lock);
    pthread_mutex_unlock(&g_vlan.lock);

    /* 4. Apply. Tear the old rules down first so stale VLAN interfaces and
     *    iptables chains do not survive into the new configuration. */
    if (apply_net) vlan_teardown_system(&g_vlan);

    int failures = apply_all(apply_net);
    if (failures > 0) {
        fprintf(stderr, "[%s] reload: %d provisioning command(s) failed, "
                "rolling back\n", BRAND_PRODUCT, failures);

        if (apply_net) vlan_teardown_system(&g_vlan);

        pthread_mutex_lock(&g_policy.lock);
        policy_adopt(&g_policy, bp2);
        pthread_mutex_unlock(&g_policy.lock);

        pthread_mutex_lock(&g_vpn.lock);
        vpn_adopt(&g_vpn, bx);
        pthread_mutex_unlock(&g_vpn.lock);

        pthread_mutex_lock(&g_vlan.lock);
        pthread_mutex_lock(&g_netconf.lock);
        vlan_adopt(&g_vlan, bv);
        netconf_adopt(&g_netconf, bn);
        pthread_mutex_unlock(&g_netconf.lock);
        pthread_mutex_unlock(&g_vlan.lock);

        apply_all(apply_net);

        if (err)
            snprintf(err, errlen,
                     "%d provisioning command(s) failed; previous configuration "
                     "restored", failures);
        goto out;
    }

    printf("[%s] reload: %d VLANs, %d ports, %d ACLs, %d WAN, %d forwards, "
           "%d aliases, %d schedules, %d routes, %d wg peers, %d tunnels\n",
           BRAND_PRODUCT, res.vlans, res.ports, res.acls, res.wans,
           res.forwards, res.aliases, res.schedules, res.routes,
           res.wg_peers, res.ipsec_tunnels);
    rc = 0;

out:
    vlan_shutdown(sv);
    netconf_shutdown(sn);
    policy_shutdown(sp);
    vpn_shutdown(sx);
    free(sv); free(sn); free(sb); free(sp); free(sx);
    free(bv); free(bn); free(bp2); free(bx);
    return rc;
}
