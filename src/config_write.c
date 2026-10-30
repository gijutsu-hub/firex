/*
 * Serialising half of the enterprise config.
 *
 * Every emitter here is paired with a reader in enterprise_config.c. When you
 * add a key to one, add it to the other -- tests/test_config.c round-trips the
 * shipped configs and will fail loudly if the two drift apart.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <arpa/inet.h>

#include "config_write.h"
#include "vpn.h"
#include "shaper.h"
#include "portal.h"
#include "ha.h"
#include "ids.h"
#include "feeds.h"
#include "response.h"
#include "netutil.h"
#include "brand.h"

static const char *cfg_bool(bool b) { return b ? "yes" : "no"; }

static const char *zone_word(zone_t z) { return zone_name(z); }

static const char *action_word(ivr_action_t a) {
    switch (a) {
        case IVR_ALLOW:     return "ALLOW";
        case IVR_LOG_ALLOW: return "LOG_ALLOW";
        case IVR_LOG_DENY:  return "LOG_DENY";
        default:            return "DENY";
    }
}

static const char *mode_word(port_mode_t m) {
    switch (m) {
        case PORT_MODE_TRUNK:    return "trunk";
        case PORT_MODE_HYBRID:   return "hybrid";
        case PORT_MODE_MIRROR:   return "mirror";
        case PORT_MODE_DISABLED: return "disabled";
        default:                 return "access";
    }
}

static const char *wan_mode_word(wan_mode_t m) {
    switch (m) {
        case WAN_STATIC:   return "static";
        case WAN_PPPOE:    return "pppoe";
        case WAN_DISABLED: return "disabled";
        default:           return "dhcp";
    }
}

static const char *proto_word(uint8_t p) {
    switch (p) {
        case 6:  return "tcp";
        case 17: return "udp";
        case 1:  return "icmp";
        default: return "*";
    }
}

/* The parser strips everything after an unquoted # or ;, and takes the text
 * between the first and last double quote. A description carrying either
 * would come back mangled, so flatten them on the way out. */
static const char *safe_desc(const char *in, char *buf, size_t len) {
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < len; p++) {
        char c = *p;
        if (c == '"' || c == '#' || c == ';' || c == '\n' || c == '\r') c = ' ';
        buf[o++] = c;
    }
    buf[o] = '\0';
    while (o && buf[o-1] == ' ') buf[--o] = '\0';
    return buf;
}

/* A bare token the parser reads with %s -- it must not contain whitespace. */
static const char *safe_token(const char *in, char *buf, size_t len) {
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < len; p++)
        buf[o++] = (*p == ' ' || *p == '\t') ? '_' : *p;
    buf[o] = '\0';
    if (!o) snprintf(buf, len, "-");
    return buf;
}

static void write_ports(FILE *f, vlan_ctx_t *v) {
    char tok[VLAN_NAME_LEN * 2];
    for (int i = 0; i < v->port_count; i++) {
        port_config_t *p = &v->ports[i];
        fprintf(f, "[port:%s]\n", p->ifname);
        fprintf(f, "label           = %s\n", safe_token(p->label, tok, sizeof(tok)));
        fprintf(f, "mode            = %s\n", mode_word(p->mode));
        fprintf(f, "zone            = %s\n", zone_word(p->zone));
        fprintf(f, "pvid            = %u\n", p->pvid);
        if (p->allowed_count) {
            fprintf(f, "allowed_vlans   = ");
            for (int j = 0; j < p->allowed_count; j++)
                fprintf(f, "%s%u", j ? "," : "", p->allowed_vlans[j]);
            fputc('\n', f);
        }
        fprintf(f, "tag_native      = %s\n", cfg_bool(p->tag_native));
        fprintf(f, "drop_untagged   = %s\n", cfg_bool(p->drop_untagged));
        fprintf(f, "stp_enabled     = %s\n", cfg_bool(p->stp_enabled));
        fprintf(f, "storm_control   = %s\n", cfg_bool(p->storm_control));
        if (p->storm_pps_limit)
            fprintf(f, "storm_pps_limit = %d\n", p->storm_pps_limit);
        fprintf(f, "enabled         = %s\n\n", cfg_bool(p->enabled));
    }
}

static void write_vlans(FILE *f, vlan_ctx_t *v) {
    char a[INET_ADDRSTRLEN], desc[VLAN_DESC_LEN * 2], tok[VLAN_NAME_LEN * 2];
    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *c = &v->vlans[i];
        fprintf(f, "[vlan:%u]\n", c->vlan_id);
        fprintf(f, "name                = %s\n", safe_token(c->name, tok, sizeof(tok)));
        if (c->description[0])
            fprintf(f, "description         = \"%s\"\n",
                    safe_desc(c->description, desc, sizeof(desc)));
        fprintf(f, "zone                = %s\n", zone_word(c->zone));
        fprintf(f, "subnet              = %s\n", fx_ip_str(c->subnet,  a, sizeof(a)));
        fprintf(f, "netmask             = %s\n", fx_ip_str(c->netmask, a, sizeof(a)));
        fprintf(f, "gateway             = %s\n", fx_ip_str(c->gateway, a, sizeof(a)));
        fprintf(f, "dhcp                = %s\n", cfg_bool(c->dhcp_enabled));
        if (c->dhcp_start)
            fprintf(f, "dhcp_start          = %s\n", fx_ip_str(c->dhcp_start, a, sizeof(a)));
        if (c->dhcp_end)
            fprintf(f, "dhcp_end            = %s\n", fx_ip_str(c->dhcp_end, a, sizeof(a)));
        if (c->dns_primary)
            fprintf(f, "dns_primary         = %s\n", fx_ip_str(c->dns_primary, a, sizeof(a)));
        if (c->dns_secondary)
            fprintf(f, "dns_secondary       = %s\n", fx_ip_str(c->dns_secondary, a, sizeof(a)));
        fprintf(f, "lease_time          = %d\n", c->lease_time);
        fprintf(f, "inter_vlan_routing  = %s\n", cfg_bool(c->inter_vlan_routing));
        fprintf(f, "internet_access     = %s\n", cfg_bool(c->internet_access));
        fprintf(f, "client_isolation    = %s\n", cfg_bool(c->client_isolation));
        fprintf(f, "dpi                 = %s\n", cfg_bool(c->dpi_enabled));
        fprintf(f, "ips                 = %s\n", cfg_bool(c->ips_enabled));
        fprintf(f, "malware_scan        = %s\n", cfg_bool(c->malware_scan));
        fprintf(f, "log_all             = %s\n", cfg_bool(c->log_all));
        fprintf(f, "captive_portal      = %s\n", cfg_bool(c->captive_portal));
        fprintf(f, "show_block_page     = %s\n", cfg_bool(c->show_block_page));
        if (c->bandwidth_down_mbps)
            fprintf(f, "bandwidth_down_mbps = %d\n", c->bandwidth_down_mbps);
        if (c->bandwidth_up_mbps)
            fprintf(f, "bandwidth_up_mbps   = %d\n", c->bandwidth_up_mbps);
        fprintf(f, "priority            = %u\n", c->priority);
        if (c->max_clients)
            fprintf(f, "max_clients         = %d\n", c->max_clients);
        fputc('\n', f);
    }
}

static void write_wan(FILE *f, netconf_ctx_t *n) {
    char a[INET_ADDRSTRLEN];
    for (int i = 0; i < n->wan_count; i++) {
        wan_config_t *w = &n->wan[i];
        fprintf(f, "[wan:%d]\n", i);
        fprintf(f, "interface        = %s\n", w->ifname);
        fprintf(f, "mode             = %s\n", wan_mode_word(w->mode));
        if (w->mode == WAN_STATIC) {
            fprintf(f, "ip               = %s\n", fx_ip_str(w->ip,      a, sizeof(a)));
            fprintf(f, "netmask          = %s\n", fx_ip_str(w->netmask, a, sizeof(a)));
            fprintf(f, "gateway          = %s\n", fx_ip_str(w->gateway, a, sizeof(a)));
        }
        if (w->dns1) fprintf(f, "dns1             = %s\n", fx_ip_str(w->dns1, a, sizeof(a)));
        if (w->dns2) fprintf(f, "dns2             = %s\n", fx_ip_str(w->dns2, a, sizeof(a)));
        if (w->mode == WAN_PPPOE) {
            fprintf(f, "pppoe_user       = %s\n", w->pppoe_user);
            fprintf(f, "pppoe_pass       = %s\n", w->pppoe_pass);
        }
        fprintf(f, "mtu              = %d\n", w->mtu);
        fprintf(f, "nat              = %s\n", cfg_bool(w->nat_enabled));
        fprintf(f, "block_private_in = %s\n", cfg_bool(w->block_private_in));
        fprintf(f, "block_bogons     = %s\n", cfg_bool(w->block_bogons));
        fprintf(f, "respond_to_ping  = %s\n", cfg_bool(w->respond_to_ping));
        fprintf(f, "upnp             = %s\n", cfg_bool(w->upnp_enabled));
        fprintf(f, "is_backup        = %s\n", cfg_bool(w->is_backup));
        fprintf(f, "priority         = %d\n", w->failover_priority);
        if (w->monitor_ip[0])
            fprintf(f, "monitor_ip       = %s\n", w->monitor_ip);
        fputc('\n', f);
    }
}

static void write_zones(FILE *f, vlan_ctx_t *v) {
    fprintf(f, "[zones]\n");
    for (int from = 0; from < ZONE_MAX; from++)
        for (int to = 0; to < ZONE_MAX; to++) {
            if (from == to) continue;
            fprintf(f, "zone_policy = %-10s %-10s %s\n",
                    zone_word(from), zone_word(to),
                    action_word(v->zone_matrix[from][to]));
        }
    fputc('\n', f);
}

static void write_acl(FILE *f, vlan_ctx_t *v) {
    char desc[VLAN_DESC_LEN * 2], sc[32], dc[32];
    fprintf(f, "[acl]\n");
    for (int i = 0; i < v->ivr_count; i++) {
        ivr_rule_t *r = &v->ivr[i];
        if (!r->enabled) continue;

        char svl[8], dvl[8], port[POLICY_NAME_LEN + 4];
        if (r->src_vlan) snprintf(svl, sizeof(svl), "%u", r->src_vlan);
        else             snprintf(svl, sizeof(svl), "*");
        if (r->dst_vlan) snprintf(dvl, sizeof(dvl), "%u", r->dst_vlan);
        else             snprintf(dvl, sizeof(dvl), "*");

        if (r->port_alias[0])
            snprintf(port, sizeof(port), "$%s", r->port_alias);
        else if (!r->dst_port_start)
            snprintf(port, sizeof(port), "*");
        else if (r->dst_port_start == r->dst_port_end)
            snprintf(port, sizeof(port), "%u", r->dst_port_start);
        else
            snprintf(port, sizeof(port), "%u-%u", r->dst_port_start, r->dst_port_end);

        fprintf(f, "rule = %-4s -> %-4s %-4s %-14s %-9s %3d \"%s\"",
                svl, dvl, proto_word(r->protocol), port,
                action_word(r->action), r->priority,
                safe_desc(r->description, desc, sizeof(desc)));

        /* Host-level match is an extension: older parsers stop at the quoted
         * description and simply ignore what follows, so emitting these keeps
         * the file readable by both. Only written when actually set. */
        if (r->src_alias[0])  fprintf(f, " src=$%s", r->src_alias);
        else if (r->src_ip)   fprintf(f, " src=%s",
                                      fx_cidr_str(r->src_ip, r->src_mask, sc, sizeof(sc)));

        if (r->dst_alias[0])  fprintf(f, " dst=$%s", r->dst_alias);
        else if (r->dst_ip)   fprintf(f, " dst=%s",
                                      fx_cidr_str(r->dst_ip, r->dst_mask, dc, sizeof(dc)));

        if (r->schedule[0])   fprintf(f, " sched=%s", r->schedule);
        fputc('\n', f);
    }
    fputc('\n', f);
}

static void write_forwards(FILE *f, netconf_ctx_t *n) {
    char a[INET_ADDRSTRLEN], cidr[32], tok[VLAN_NAME_LEN * 2];
    fprintf(f, "[forward]\n");
    for (int i = 0; i < n->forward_count; i++) {
        port_forward_t *fw = &n->forwards[i];
        if (!fw->enabled) continue;
        fprintf(f, "fwd = %-14s %-4s %-6u %-16s %-6u %-4u %-18s %s\n",
                safe_token(fw->name, tok, sizeof(tok)),
                fw->protocol == 17 ? "udp" : "tcp",
                fw->wan_port_start,
                fx_ip_str(fw->internal_ip, a, sizeof(a)),
                fw->internal_port,
                fw->dst_vlan,
                fx_cidr_str(fw->source_restrict, fw->source_mask, cidr, sizeof(cidr)),
                cfg_bool(fw->log_hits));
    }
    fputc('\n', f);
}

static void write_aliases(FILE *f, policy_ctx_t *p) {
    if (!p || !p->alias_count) return;

    char entries[2048], desc[POLICY_DESC_LEN * 2];
    for (int i = 0; i < p->alias_count; i++) {
        alias_t *a = &p->aliases[i];
        if (!a->enabled || a->count <= 0) continue;
        fprintf(f, "[alias:%s]\n", a->name);
        fprintf(f, "kind        = %s\n", policy_alias_kind_str(a->kind));
        if (a->description[0])
            fprintf(f, "description = \"%s\"\n",
                    safe_desc(a->description, desc, sizeof(desc)));
        fprintf(f, "entries     = %s\n\n",
                policy_entries_str(a, entries, sizeof(entries)));
    }
}

static void write_schedules(FILE *f, policy_ctx_t *p) {
    if (!p || !p->schedule_count) return;

    char days[64], hh[8], desc[POLICY_DESC_LEN * 2];
    for (int i = 0; i < p->schedule_count; i++) {
        schedule_t *sc = &p->schedules[i];
        if (!sc->enabled) continue;
        fprintf(f, "[schedule:%s]\n", sc->name);
        if (sc->description[0])
            fprintf(f, "description = \"%s\"\n",
                    safe_desc(sc->description, desc, sizeof(desc)));
        fprintf(f, "days        = %s\n", policy_days_str(sc->days, days, sizeof(days)));
        fprintf(f, "start       = %s\n", policy_hhmm_str(sc->start_min, hh, sizeof(hh)));
        fprintf(f, "end         = %s\n\n", policy_hhmm_str(sc->end_min, hh, sizeof(hh)));
    }
}

static void write_routes(FILE *f, netconf_ctx_t *n) {
    if (!n->route_count) return;

    char dbuf[INET_ADDRSTRLEN], gbuf[INET_ADDRSTRLEN], desc[VLAN_DESC_LEN * 2];
    fprintf(f, "[route]\n");
    for (int i = 0; i < n->route_count; i++) {
        static_route_t *r = &n->routes[i];
        if (!r->enabled) continue;
        fprintf(f, "route = %s/%-3d %-16s %-10s %3d \"%s\"\n",
                fx_ip_str(r->dest, dbuf, sizeof(dbuf)),
                fx_netmask_to_cidr(r->mask),
                fx_ip_str(r->gateway, gbuf, sizeof(gbuf)),
                r->ifname[0] ? r->ifname : "-",
                r->metric,
                safe_desc(r->description, desc, sizeof(desc)));
    }
    fputc('\n', f);
}

static void write_shaping(FILE *f, netconf_ctx_t *n) {
    shaper_cfg_t *c = &n->shaping;
    if (!c->enabled && !c->wan_up_mbps && !c->wan_down_mbps) return;

    fprintf(f, "[shaping]\n");
    fprintf(f, "enabled           = %s\n", cfg_bool(c->enabled));
    if (c->wan_up_mbps)   fprintf(f, "wan_up_mbps       = %d\n", c->wan_up_mbps);
    if (c->wan_down_mbps) fprintf(f, "wan_down_mbps     = %d\n", c->wan_down_mbps);
    fprintf(f, "qdisc             = %s\n", qdisc_name(c->qdisc));
    fprintf(f, "codel_target_ms   = %d\n",
            c->codel_target_ms ? c->codel_target_ms : 5);
    fprintf(f, "codel_interval_ms = %d\n",
            c->codel_interval_ms ? c->codel_interval_ms : 100);
    fprintf(f, "ecn               = %s\n", cfg_bool(c->ecn));
    fprintf(f, "ingress_shaping   = %s\n\n", cfg_bool(c->ingress_shaping));
}

static void write_portal(FILE *f, netconf_ctx_t *n) {
    portal_cfg_t *c = &n->portal;
    if (!c->enabled && !c->radius_host[0] && !c->terms[0]) return;

    char desc[PORTAL_TERMS_LEN * 2];
    fprintf(f, "[portal]\n");
    fprintf(f, "enabled           = %s\n", cfg_bool(c->enabled));
    fprintf(f, "auth              = %s\n", portal_auth_name(c->auth));
    fprintf(f, "session_minutes   = %d\n",
            c->session_minutes ? c->session_minutes : 240);
    fprintf(f, "idle_minutes      = %d\n",
            c->idle_minutes ? c->idle_minutes : 30);
    if (c->terms[0])
        fprintf(f, "terms             = \"%s\"\n",
                safe_desc(c->terms, desc, sizeof(desc)));
    if (c->radius_host[0]) {
        fprintf(f, "radius_host       = %s\n", c->radius_host);
        fprintf(f, "radius_port       = %u\n",
                c->radius_port ? c->radius_port : 1812);
        fprintf(f, "radius_secret     = %s\n", c->radius_secret);
        fprintf(f, "radius_timeout_ms = %d\n",
                c->radius_timeout_ms ? c->radius_timeout_ms : 3000);
        fprintf(f, "radius_retries    = %d\n",
                c->radius_retries ? c->radius_retries : 2);
    }
    if (c->nas_id[0]) fprintf(f, "nas_id            = %s\n", c->nas_id);
    fputc('\n', f);
}

static void write_threat(FILE *f, netconf_ctx_t *n) {
    threat_cfg_t *t = &n->threat;
    if (!t->enabled && !t->rules_path[0] && !n->feed_count) return;

    fprintf(f, "[threat]\n");
    fprintf(f, "enabled       = %s\n", cfg_bool(t->enabled));
    fprintf(f, "inline        = %s\n", cfg_bool(t->inline_mode));
    if (t->rules_path[0])
        fprintf(f, "rules         = %s\n", t->rules_path);
    fprintf(f, "feeds_enabled = %s\n\n", cfg_bool(t->feeds_enabled));

    for (int i = 0; i < n->feed_count; i++) {
        feed_t *fd = &n->feeds[i];
        fprintf(f, "[feed:%s]\n", fd->name);
        fprintf(f, "kind    = %s\n", feed_kind_name(fd->kind));
        fprintf(f, "url     = %s\n", fd->url);
        fprintf(f, "refresh = %d\n", fd->refresh_minutes);
        fprintf(f, "enabled = %s\n\n", cfg_bool(fd->enabled));
    }
}

static void write_console(FILE *f, netconf_ctx_t *n) {
    if (!n->console_port && !n->console_bind[0] && !n->console_tls_set &&
        !n->console_tls_cert[0] && !n->console_tls_key[0]) return;
    fprintf(f, "[console]\n");
    if (n->console_port)    fprintf(f, "port = %d\n", n->console_port);
    if (n->console_bind[0]) fprintf(f, "bind = %s\n", n->console_bind);
    /*
     * Only written when the config said so. TLS defaults on, and writing
     * "tls = yes" into every saved config would make the default look like
     * a choice somebody made -- so turning the default off later would
     * silently not apply to any appliance that had ever pressed Save.
     */
    if (n->console_tls_set)
        fprintf(f, "tls = %s\n", cfg_bool(n->console_tls));
    if (n->console_tls_cert[0])
        fprintf(f, "tls_cert = %s\n", n->console_tls_cert);
    if (n->console_tls_key[0])
        fprintf(f, "tls_key = %s\n", n->console_tls_key);
    fprintf(f, "\n");
}

static void write_malware(FILE *f, netconf_ctx_t *n) {
    mw_cfg_t *m = &n->malware;
    if (!m->enabled && !m->db_path[0]) return;

    fprintf(f, "[malware]\n");
    fprintf(f, "enabled       = %s\n", cfg_bool(m->enabled));
    fprintf(f, "block         = %s\n", cfg_bool(m->block));
    fprintf(f, "scan_uploads  = %s\n", cfg_bool(m->scan_uploads));
    if (m->max_object_kb)     fprintf(f, "max_object_kb = %d\n", m->max_object_kb);
    if (m->flow_idle_seconds) fprintf(f, "flow_idle     = %d\n", m->flow_idle_seconds);
    if (m->db_path[0])        fprintf(f, "database      = %s\n", m->db_path);
    fprintf(f, "\n");
}

static void write_airgap(FILE *f, netconf_ctx_t *n) {
    ag_cfg_t *a = &n->airgap;
    /*
     * Always written, even at its default. Skipping the section while the
     * mode happens to be "connected" also threw away require_time_sync
     * and log_denied, so an operator who had turned one of them off got
     * it silently turned back on by the next save. A security setting
     * that does not survive a round trip is worse than one that was
     * never offered.
     */

    fprintf(f, "[airgap]\n");
    fprintf(f, "mode              = %s\n", airgap_mode_name(a->mode));
    fprintf(f, "require_time_sync = %s\n", cfg_bool(a->require_time_sync));
    fprintf(f, "log_denied        = %s\n", cfg_bool(a->log_denied));

    for (int i = 0; i < n->airgap_window_count; i++) {
        ag_window_t *w = &n->airgap_windows[i];
        if (!w->used) continue;
        char days[8];
        static const char L[7] = { 'S','M','T','W','T','F','S' };
        for (int d = 0; d < 7; d++) days[d] = (w->days & (1u << d)) ? L[d] : '-';
        days[7] = 0;
        fprintf(f, "window            = %s,%s,%02u:%02u,%02u:%02u,%d,%d\n",
                w->name, days,
                w->start_min / 60, w->start_min % 60,
                w->end_min   / 60, w->end_min   % 60,
                w->allow_in ? 1 : 0, w->allow_out ? 1 : 0);
    }
    fprintf(f, "\n");
}

static void write_response(FILE *f, netconf_ctx_t *n) {
    response_cfg_t *r = &n->response;
    if (!r->enabled && !r->threshold) return;

    fprintf(f, "[response]\n");
    fprintf(f, "enabled           = %s\n", cfg_bool(r->enabled));
    fprintf(f, "threshold         = %d\n", r->threshold ? r->threshold : 10);
    fprintf(f, "block_minutes     = %d\n",
            r->block_minutes ? r->block_minutes : 15);
    fprintf(f, "escalate          = %s\n", cfg_bool(r->escalate));
    fprintf(f, "max_block_minutes = %d\n",
            r->max_block_minutes ? r->max_block_minutes : 1440);
    fprintf(f, "decay_minutes     = %d\n",
            r->decay_minutes ? r->decay_minutes : 60);
    fprintf(f, "quarantine        = %s\n", cfg_bool(r->quarantine));
    fprintf(f, "notify            = %s\n\n", cfg_bool(r->notify));
}

static void write_ha(FILE *f, netconf_ctx_t *n) {
    ha_cfg_t *c = &n->ha;
    if (!c->enabled && !c->peer_address[0]) return;

    fprintf(f, "[ha]\n");
    fprintf(f, "enabled          = %s\n", cfg_bool(c->enabled));
    fprintf(f, "role             = %s\n", ha_role_name(c->role));
    if (c->peer_address[0])
        fprintf(f, "peer_address     = %s\n", c->peer_address);
    if (c->sync_address[0])
        fprintf(f, "sync_address     = %s\n", c->sync_address);
    if (c->sync_interface[0])
        fprintf(f, "sync_interface   = %s\n", c->sync_interface);
    fprintf(f, "vrrp_id          = %d\n", c->vrrp_id ? c->vrrp_id : HA_DEFAULT_VRID);
    if (c->vrrp_password[0])
        fprintf(f, "vrrp_password    = %s\n", c->vrrp_password);
    fprintf(f, "priority         = %d\n",
            c->priority ? c->priority
                        : (c->role == HA_ROLE_PRIMARY ? 150 : 100));
    fprintf(f, "advert_interval  = %d\n",
            c->advert_interval ? c->advert_interval : 1);
    fprintf(f, "preempt          = %s\n", cfg_bool(c->preempt));
    fprintf(f, "conntrack_sync   = %s\n", cfg_bool(c->conntrack_sync));
    if (c->conntrack_sync)
        fprintf(f, "conntrack_port   = %d\n",
                c->conntrack_port ? c->conntrack_port : HA_DEFAULT_CT_PORT);
    fprintf(f, "config_sync      = %s\n", cfg_bool(c->config_sync));
    if (c->config_sync) {
        fprintf(f, "config_sync_port = %d\n",
                c->config_sync_port ? c->config_sync_port : HA_DEFAULT_SYNC_PORT);
        if (c->sync_secret[0])
            fprintf(f, "sync_secret      = %s\n", c->sync_secret);
    }
    fputc('\n', f);
}

static void write_telemetry(FILE *f, netconf_ctx_t *n) {
    telemetry_cfg_t *t = &n->telemetry;
    if (!t->syslog_host[0] && !t->netflow_host[0] && !t->history_interval) return;

    fprintf(f, "[telemetry]\n");
    if (t->syslog_host[0]) {
        fprintf(f, "syslog_host         = %s\n", t->syslog_host);
        fprintf(f, "syslog_port         = %u\n",
                t->syslog_port ? t->syslog_port : 514);
        fprintf(f, "syslog_proto        = %s\n", t->syslog_tcp ? "tcp" : "udp");
        fprintf(f, "syslog_facility     = %d\n",
                t->syslog_facility ? t->syslog_facility : 16);
        fprintf(f, "syslog_min_severity = %d\n",
                t->syslog_min_severity ? t->syslog_min_severity : 6);
    }
    if (t->netflow_host[0]) {
        fprintf(f, "netflow_host        = %s\n", t->netflow_host);
        fprintf(f, "netflow_port        = %u\n",
                t->netflow_port ? t->netflow_port : 2055);
        fprintf(f, "netflow_interval    = %d\n",
                t->netflow_interval ? t->netflow_interval : 60);
    }
    if (t->history_interval)
        fprintf(f, "history_interval    = %d\n", t->history_interval);
    fputc('\n', f);
}

static void write_monitor(FILE *f, netconf_ctx_t *n) {
    if (!n->monitor_interval && !n->monitor_timeout_ms &&
        !n->monitor_fail && !n->monitor_ok) return;

    fprintf(f, "[monitor]\n");
    if (n->monitor_interval)   fprintf(f, "interval       = %d\n", n->monitor_interval);
    if (n->monitor_timeout_ms) fprintf(f, "timeout_ms     = %d\n", n->monitor_timeout_ms);
    if (n->monitor_fail)       fprintf(f, "fail_threshold = %d\n", n->monitor_fail);
    if (n->monitor_ok)         fprintf(f, "ok_threshold   = %d\n", n->monitor_ok);
    fputc('\n', f);
}

static void write_wireguard(FILE *f, vpn_ctx_t *vp) {
    if (!vp || !vp->wg_count) return;

    char a[INET_ADDRSTRLEN], desc[VLAN_DESC_LEN * 2];
    for (int i = 0; i < vp->wg_count; i++) {
        wg_iface_t *w = &vp->wg[i];
        fprintf(f, "[wireguard:%s]\n", w->ifname);
        if (w->description[0])
            fprintf(f, "description   = \"%s\"\n",
                    safe_desc(w->description, desc, sizeof(desc)));
        fprintf(f, "enabled       = %s\n", cfg_bool(w->enabled));
        fprintf(f, "listen_port   = %u\n", w->listen_port);
        if (w->address) {
            fprintf(f, "address       = %s\n", fx_ip_str(w->address, a, sizeof(a)));
            fprintf(f, "netmask       = %s\n", fx_ip_str(w->netmask, a, sizeof(a)));
        }
        fprintf(f, "mtu           = %d\n", w->mtu);
        fprintf(f, "zone          = %s\n", zone_word(w->zone));
        if (w->dns) fprintf(f, "dns           = %s\n", fx_ip_str(w->dns, a, sizeof(a)));
        /* The private key lives here because this file is the system of
         * record; it is written 0600 for exactly that reason. */
        if (w->private_key[0])
            fprintf(f, "private_key   = %s\n", w->private_key);
        fputc('\n', f);
    }
}

static void write_wg_peers(FILE *f, vpn_ctx_t *vp) {
    if (!vp || !vp->peer_count) return;

    char nb[64], desc[VLAN_DESC_LEN * 2];
    for (int i = 0; i < vp->peer_count; i++) {
        wg_peer_t *p = &vp->peers[i];
        fprintf(f, "[wgpeer:%s]\n", p->name);
        if (p->description[0])
            fprintf(f, "description   = \"%s\"\n",
                    safe_desc(p->description, desc, sizeof(desc)));
        fprintf(f, "interface     = %s\n", p->ifname);
        fprintf(f, "enabled       = %s\n", cfg_bool(p->enabled));
        fprintf(f, "public_key    = %s\n", p->public_key);
        if (p->preshared_key[0])
            fprintf(f, "preshared_key = %s\n", p->preshared_key);
        if (p->allowed_count) {
            fprintf(f, "allowed_ips   = ");
            for (int j = 0; j < p->allowed_count; j++)
                fprintf(f, "%s%s", j ? ", " : "",
                        fx_cidr_str(p->allowed[j].ip, p->allowed[j].mask,
                                    nb, sizeof(nb)));
            fputc('\n', f);
        }
        if (p->endpoint_host[0])
            fprintf(f, "endpoint      = %s:%u\n",
                    p->endpoint_host, p->endpoint_port);
        if (p->keepalive > 0)
            fprintf(f, "keepalive     = %d\n", p->keepalive);
        fprintf(f, "zone          = %s\n\n", zone_word(p->zone));
    }
}

static void write_ipsec(FILE *f, vpn_ctx_t *vp) {
    if (!vp || !vp->tunnel_count) return;

    char lb[64], rb[64], desc[VLAN_DESC_LEN * 2];
    for (int i = 0; i < vp->tunnel_count; i++) {
        ipsec_tunnel_t *t = &vp->tunnels[i];
        fprintf(f, "[ipsec:%s]\n", t->name);
        if (t->description[0])
            fprintf(f, "description   = \"%s\"\n",
                    safe_desc(t->description, desc, sizeof(desc)));
        fprintf(f, "enabled       = %s\n", cfg_bool(t->enabled));
        fprintf(f, "remote_host   = %s\n", t->remote_host);
        if (t->local_id[0])  fprintf(f, "local_id      = %s\n", t->local_id);
        if (t->remote_id[0]) fprintf(f, "remote_id     = %s\n", t->remote_id);
        fprintf(f, "local_subnet  = %s\n",
                fx_cidr_str(t->local_subnet, t->local_mask, lb, sizeof(lb)));
        fprintf(f, "remote_subnet = %s\n",
                fx_cidr_str(t->remote_subnet, t->remote_mask, rb, sizeof(rb)));
        fprintf(f, "version       = %s\n", ike_version_str(t->version));
        fprintf(f, "ike_proposal  = %s\n", t->ike_proposal);
        fprintf(f, "esp_proposal  = %s\n", t->esp_proposal);
        fprintf(f, "ike_lifetime  = %d\n", t->ike_lifetime);
        fprintf(f, "esp_lifetime  = %d\n", t->esp_lifetime);
        fprintf(f, "dpd           = %s\n", cfg_bool(t->dpd));
        if (t->dpd) fprintf(f, "dpd_delay     = %d\n", t->dpd_delay);
        fprintf(f, "zone          = %s\n", zone_word(t->zone));
        if (t->psk[0]) fprintf(f, "psk           = %s\n", t->psk);
        fputc('\n', f);
    }
}

int firex_save_enterprise_config(const char *path,
                                 vlan_ctx_t *v,
                                 netconf_ctx_t *n,
                                 blockpage_ctx_t *bp,
                                 const cfg_meta_t *meta) {
    return firex_save_enterprise_config_ex(path, v, n, bp, NULL, NULL, meta);
}

int firex_save_enterprise_config_ex(const char *path,
                                    vlan_ctx_t *v,
                                    netconf_ctx_t *n,
                                    blockpage_ctx_t *bp,
                                    policy_ctx_t *pol,
                                    vpn_ctx_t *vpn,
                                    const cfg_meta_t *meta) {
    if (!path || !v || !n || !bp) return -1;

    char tmp[1024];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return -1;

    /*
     * The configuration carries secrets -- PPPoE passwords, WireGuard private
     * keys, IPsec pre-shared keys -- so it is 0600 from the moment it exists
     * rather than being chmod'ed afterwards, which would leave a window where
     * it is readable.
     */
    int cfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (cfd < 0) return -1;
    FILE *f = fdopen(cfd, "w");
    if (!f) { close(cfd); unlink(tmp); return -1; }

    pthread_mutex_lock(&v->lock);
    pthread_mutex_lock(&n->lock);
    if (pol) pthread_mutex_lock(&pol->lock);
    if (vpn) pthread_mutex_lock(&vpn->lock);

    fprintf(f, "# %s %s enterprise configuration\n", BRAND_PRODUCT, BRAND_VERSION);
    fprintf(f, "# Generated by %s -- edits here are replaced on the next save.\n",
            BRAND_DAEMON);
    if (meta && meta->revision > 0) {
        char when[64];
        time_t t = meta->when ? meta->when : time(NULL);
        struct tm tmv;
        gmtime_r(&t, &tmv);
        strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tmv);
        fprintf(f, "# @rev    %d\n", meta->revision);
        fprintf(f, "# @time   %s\n", when);
        fprintf(f, "# @author %s\n", meta->author[0] ? meta->author : "system");
        if (meta->note[0]) {
            char nbuf[CFG_NOTE_LEN * 2];
            fprintf(f, "# @note   %s\n", safe_desc(meta->note, nbuf, sizeof(nbuf)));
        }
    }
    fputc('\n', f);

    fprintf(f, "[system]\n");
    fprintf(f, "domain        = %s\n", n->domain[0] ? n->domain : "localdomain");
    fprintf(f, "organisation  = %s\n", bp->org_name);
    fprintf(f, "admin_contact = %s\n\n", bp->admin_contact);

    write_wan(f, n);
    write_monitor(f, n);
    write_telemetry(f, n);
    write_shaping(f, n);
    write_portal(f, n);
    write_ha(f, n);
    write_threat(f, n);
    write_console(f, n);
    write_malware(f, n);
    write_airgap(f, n);
    write_response(f, n);
    write_ports(f, v);
    write_vlans(f, v);
    write_aliases(f, pol);
    write_schedules(f, pol);
    write_zones(f, v);
    write_acl(f, v);
    write_forwards(f, n);
    write_routes(f, n);
    write_wireguard(f, vpn);
    write_wg_peers(f, vpn);
    write_ipsec(f, vpn);

    fprintf(f, "[blockpage]\n");
    fprintf(f, "enabled        = %s\n", cfg_bool(bp->enabled));
    fprintf(f, "port           = %d\n", bp->port ? bp->port : BLOCKPAGE_PORT);
    fprintf(f, "org_name       = %s\n", bp->org_name);
    fprintf(f, "admin_contact  = %s\n", bp->admin_contact);
    fprintf(f, "show_technical = %s\n", cfg_bool(bp->show_technical));
    fprintf(f, "allow_override = %s\n", cfg_bool(bp->allow_override));
    fprintf(f, "show_logo      = %s\n", cfg_bool(bp->show_logo));

    if (vpn) pthread_mutex_unlock(&vpn->lock);
    if (pol) pthread_mutex_unlock(&pol->lock);
    pthread_mutex_unlock(&n->lock);
    pthread_mutex_unlock(&v->lock);

    /* Durability: the rename is only atomic with respect to a crash if the
     * bytes are on disk first. */
    int rc = 0;
    if (fflush(f) != 0) rc = -1;
    int fd = fileno(f);
    if (rc == 0 && fd >= 0 && fsync(fd) != 0) rc = -1;
    if (fclose(f) != 0) rc = -1;

    if (rc != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }

    /* Fsync the directory too, or the rename itself can be lost. */
    char dirbuf[1024];
    snprintf(dirbuf, sizeof(dirbuf), "%s", path);
    char *slash = strrchr(dirbuf, '/');
    if (slash) {
        *slash = '\0';
        int dfd = open(dirbuf[0] ? dirbuf : "/", O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }
    return 0;
}

int vlan_save_config(vlan_ctx_t *v, const char *file) {
    /* The segmentation model alone is not a loadable config -- WAN, forwards
     * and the portal live in the same file. Emit a complete one using empty
     * defaults for the parts this caller does not own, so the result still
     * round-trips. */
    static netconf_ctx_t   nblank;
    static blockpage_ctx_t bblank;
    static bool            inited;

    if (!inited) {
        memset(&nblank, 0, sizeof(nblank));
        memset(&bblank, 0, sizeof(bblank));
        pthread_mutex_init(&nblank.lock, NULL);
        snprintf(nblank.domain, sizeof(nblank.domain), "localdomain");
        snprintf(bblank.org_name, sizeof(bblank.org_name), "%s", BRAND_VENDOR);
        snprintf(bblank.admin_contact, sizeof(bblank.admin_contact),
                 "%s", BRAND_SUPPORT_EMAIL);
        bblank.enabled = true;
        bblank.port    = BLOCKPAGE_PORT;
        inited = true;
    }
    return firex_save_enterprise_config(file, v, &nblank, &bblank, NULL);
}

int firex_read_config_meta(const char *path, cfg_meta_t *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(out, 0, sizeof(*out));

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '#') {
            if (line[0] == '[') break;      /* header region is over */
            continue;
        }
        char key[32], val[256];
        if (sscanf(line, "# @%31s %255[^\n]", key, val) != 2) continue;

        char *v = val;
        while (*v == ' ' || *v == '\t') v++;
        size_t vl = strlen(v);
        while (vl && (v[vl-1] == ' ' || v[vl-1] == '\r')) v[--vl] = '\0';

        if (!strcmp(key, "rev")) { out->revision = atoi(v); found = true; }
        else if (!strcmp(key, "author")) snprintf(out->author, CFG_AUTHOR_LEN, "%s", v);
        else if (!strcmp(key, "note"))   snprintf(out->note,   CFG_NOTE_LEN,   "%s", v);
        else if (!strcmp(key, "time")) {
            struct tm tmv;
            memset(&tmv, 0, sizeof(tmv));
            if (strptime(v, "%Y-%m-%dT%H:%M:%SZ", &tmv)) out->when = timegm(&tmv);
        }
    }
    fclose(f);
    return found ? 0 : -1;
}
