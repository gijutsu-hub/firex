#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "enterprise.h"
#include "policy.h"
#include "vpn.h"
#include "shaper.h"
#include "portal.h"
#include "ha.h"
#include "ids.h"
#include "feeds.h"
#include "response.h"
#include "netutil.h"
#include "brand.h"

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static void strip_comment(char *s) {
    bool inq = false;
    for (char *p = s; *p; p++) {
        if (*p == '"') inq = !inq;
        if (!inq && (*p == ';' || *p == '#')) { *p = '\0'; return; }
    }
}

/* inet_addr() cannot tell 255.255.255.255 from a parse failure, so validate. */
static uint32_t parse_ip(const char *s) {
    struct in_addr a;
    if (!s || inet_pton(AF_INET, s, &a) != 1) return 0;
    return a.s_addr;
}

static zone_t parse_zone(const char *s) {
    if (!strcasecmp(s, "WAN"))        return ZONE_WAN;
    if (!strcasecmp(s, "LAN"))        return ZONE_LAN;
    if (!strcasecmp(s, "DMZ"))        return ZONE_DMZ;
    if (!strcasecmp(s, "GUEST"))      return ZONE_GUEST;
    if (!strcasecmp(s, "IOT"))        return ZONE_IOT;
    if (!strcasecmp(s, "VOIP"))       return ZONE_VOIP;
    if (!strcasecmp(s, "MGMT"))       return ZONE_MGMT;
    if (!strcasecmp(s, "QUARANTINE")) return ZONE_QUARANTINE;
    if (!strcasecmp(s, "VPN"))        return ZONE_VPN;
    return ZONE_LAN;
}

static ivr_action_t parse_action(const char *s) {
    if (!strcasecmp(s, "DENY"))      return IVR_DENY;
    if (!strcasecmp(s, "LOG_DENY"))  return IVR_LOG_DENY;
    if (!strcasecmp(s, "LOG_ALLOW")) return IVR_LOG_ALLOW;
    return IVR_ALLOW;
}

/* Pull an optional "<key><value>" token out of an ACL line. Only the text
 * after the quoted description is searched, so a description that happens to
 * contain "src=" is never mistaken for a match clause. */
static bool parse_opt_token(const char *line, const char *key,
                            char *out, size_t outlen) {
    const char *tail = strrchr(line, '"');
    tail = tail ? tail + 1 : line;

    const char *p = strstr(tail, key);
    if (!p) return false;
    if (p != tail && p[-1] != ' ' && p[-1] != '\t') return false;
    p += strlen(key);

    size_t i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\t') {
        /* Truncating here would turn a typo into a reference that resolves to
         * nothing, which reads as "matches everything" to anyone skimming the
         * rule. Reject it instead. */
        if (i + 1 >= outlen) return false;
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
    return i > 0;
}

/* Copies a $ALIAS / schedule reference, refusing one that cannot fit. */
static bool copy_ref(char *dst, size_t dstlen, const char *src, const char *what) {
    size_t n = strlen(src);
    if (!n || n >= dstlen) {
        fprintf(stderr, "[%s] %s reference '%s' is not a usable name; ignored\n",
                BRAND_PRODUCT, what, src);
        return false;
    }
    memcpy(dst, src, n + 1);
    return true;
}

static bool yes(const char *s) {
    return !strcasecmp(s, "yes") || !strcasecmp(s, "true") || !strcmp(s, "1");
}

/* ═══════════════════════════════════════════════════════════
 *  Master enterprise config loader
 * ═══════════════════════════════════════════════════════════ */
int firex_load_enterprise_config(const char *path,
                                 vlan_ctx_t *v,
                                 netconf_ctx_t *n,
                                 blockpage_ctx_t *bp) {
    return firex_load_enterprise_config_ex(path, v, n, bp, NULL, NULL);
}

int firex_load_enterprise_config_ex(const char *path,
                                    vlan_ctx_t *v,
                                    netconf_ctx_t *n,
                                    blockpage_ctx_t *bp,
                                    policy_ctx_t *pol,
                                    vpn_ctx_t *vpn) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[%s] Cannot open config: %s\n", BRAND_PRODUCT, path);
        return -1;
    }

    char line[1024], section[64] = "", sect_arg[64] = "";
    vlan_config_t cur_vlan;  bool in_vlan = false;
    port_config_t cur_port;  bool in_port = false;
    wan_config_t  cur_wan;   bool in_wan  = false;
    alias_t       cur_alias; bool in_alias = false;
    schedule_t    cur_sched; bool in_sched = false;
    wg_iface_t    cur_wg;    bool in_wg    = false;
    wg_peer_t     cur_peer;  bool in_peer  = false;
    ipsec_tunnel_t cur_tun;  bool in_tun   = false;
    feed_t        cur_feed;  bool in_feed  = false;
    int skipped_vlans = 0, skipped_acl = 0;
    int skipped_alias = 0, skipped_sched = 0, skipped_route = 0;
    int skipped_vpn = 0;
    int dup_keys = 0;

    /*
     * Keys seen in the current section instance. A repeated key silently
     * takes the last value, which in a firewall config means a setting that
     * reads one way on the page and behaves another. Worth saying out loud.
     * Sections whose keys repeat by design are exempt below.
     */
    char seen[64][40];
    int  seen_count = 0;

    #define FLUSH_VLAN() do { if (in_vlan) { \
            if (vlan_add(v, &cur_vlan) != 0) { skipped_vlans++; } \
            in_vlan = false; } } while (0)
    #define FLUSH_PORT() do { if (in_port) { port_configure(v, &cur_port); in_port = false; } } while (0)
    #define FLUSH_WAN()  do { if (in_wan) { \
            if (n->wan_count < 2) { n->wan[n->wan_count++] = cur_wan; } \
            in_wan = false; } } while (0)
    #define FLUSH_ALIAS() do { if (in_alias) { \
            if (!pol || policy_add_alias(pol, &cur_alias) != 0) skipped_alias++; \
            in_alias = false; } } while (0)
    #define FLUSH_SCHED() do { if (in_sched) { \
            if (!pol || policy_add_schedule(pol, &cur_sched) != 0) skipped_sched++; \
            in_sched = false; } } while (0)
    #define FLUSH_WG()   do { if (in_wg) { \
            if (!vpn || vpn_add_wg(vpn, &cur_wg) != 0) skipped_vpn++; \
            in_wg = false; } } while (0)
    #define FLUSH_PEER() do { if (in_peer) { \
            if (!vpn || vpn_add_peer(vpn, &cur_peer) != 0) skipped_vpn++; \
            in_peer = false; } } while (0)
    #define FLUSH_TUN()  do { if (in_tun) { \
            if (!vpn || vpn_add_tunnel(vpn, &cur_tun) != 0) skipped_vpn++; \
            in_tun = false; } } while (0)
    #define FLUSH_FEED() do { if (in_feed) { \
            if (n->feed_count < FEED_MAX_FEEDS) n->feeds[n->feed_count++] = cur_feed; \
            in_feed = false; } } while (0)

    while (fgets(line, sizeof(line), fp)) {
        strip_comment(line);
        char *l = trim(line);
        if (!*l) continue;

        /* ── Section header ── */
        if (*l == '[') {
            FLUSH_VLAN(); FLUSH_PORT(); FLUSH_WAN();
            FLUSH_ALIAS(); FLUSH_SCHED();
            FLUSH_WG(); FLUSH_PEER(); FLUSH_TUN(); FLUSH_FEED();
            seen_count = 0;

            char hdr[128] = "";
            sscanf(l, "[%127[^]]", hdr);
            char *colon = strchr(hdr, ':');
            if (colon) {
                *colon = '\0';
                snprintf(section,  sizeof(section),  "%s", trim(hdr));
                snprintf(sect_arg, sizeof(sect_arg), "%s", trim(colon + 1));
            } else {
                snprintf(section, sizeof(section), "%s", trim(hdr));
                sect_arg[0] = '\0';
            }

            if (!strcmp(section, "vlan")) {
                memset(&cur_vlan, 0, sizeof(cur_vlan));
                cur_vlan.vlan_id         = (uint16_t)atoi(sect_arg);
                cur_vlan.enabled         = true;
                cur_vlan.lease_time      = 86400;
                cur_vlan.priority        = 3;
                cur_vlan.show_block_page = true;
                in_vlan = true;
            } else if (!strcmp(section, "port")) {
                memset(&cur_port, 0, sizeof(cur_port));
                snprintf(cur_port.ifname, IFNAME_LEN, "%s", sect_arg);
                cur_port.enabled = true;
                in_port = true;
            } else if (!strcmp(section, "wan")) {
                memset(&cur_wan, 0, sizeof(cur_wan));
                cur_wan.mtu = 1500;
                cur_wan.nat_enabled = true;
                in_wan = true;
            } else if (!strcmp(section, "alias")) {
                memset(&cur_alias, 0, sizeof(cur_alias));
                snprintf(cur_alias.name, POLICY_NAME_LEN, "%s", sect_arg);
                cur_alias.kind    = ALIAS_NETWORK;
                cur_alias.enabled = true;
                in_alias = true;
            } else if (!strcmp(section, "schedule")) {
                memset(&cur_sched, 0, sizeof(cur_sched));
                snprintf(cur_sched.name, POLICY_NAME_LEN, "%s", sect_arg);
                cur_sched.enabled = true;
                in_sched = true;
            } else if (!strcmp(section, "wireguard")) {
                memset(&cur_wg, 0, sizeof(cur_wg));
                snprintf(cur_wg.ifname, IFNAME_LEN, "%s", sect_arg);
                cur_wg.enabled     = true;
                cur_wg.listen_port = 51820;
                cur_wg.mtu         = 1420;
                cur_wg.zone        = ZONE_VPN;
                in_wg = true;
            } else if (!strcmp(section, "wgpeer")) {
                memset(&cur_peer, 0, sizeof(cur_peer));
                snprintf(cur_peer.name, VPN_NAME_LEN, "%s", sect_arg);
                cur_peer.enabled = true;
                cur_peer.zone    = ZONE_VPN;
                snprintf(cur_peer.ifname, IFNAME_LEN, "wg0");
                in_peer = true;
            } else if (!strcmp(section, "feed")) {
                memset(&cur_feed, 0, sizeof(cur_feed));
                snprintf(cur_feed.name, FEED_NAME_LEN, "%s", sect_arg);
                cur_feed.enabled = true;
                cur_feed.kind = FEED_IP;
                cur_feed.refresh_minutes = 1440;
                in_feed = true;
            } else if (!strcmp(section, "ipsec")) {
                memset(&cur_tun, 0, sizeof(cur_tun));
                snprintf(cur_tun.name, VPN_NAME_LEN, "%s", sect_arg);
                cur_tun.enabled   = true;
                cur_tun.zone      = ZONE_VPN;
                cur_tun.version   = IKE_V2;
                cur_tun.dpd       = true;
                cur_tun.dpd_delay = 30;
                in_tun = true;
            }
            continue;
        }

        /* ── key = value ── */
        char *eq = strchr(l, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(l);
        char *val = trim(eq + 1);
        if (*val == '"') { val++; char *q = strrchr(val, '"'); if (q) *q = '\0'; }

        /* "rule", "fwd", "route" and "zone_policy" are list entries, not
         * settings, so repeating them is how the format works. */
        bool repeats_by_design =
            !strcmp(key, "rule") || !strcmp(key, "fwd") ||
            !strcmp(key, "route") || !strcmp(key, "zone_policy");

        if (!repeats_by_design) {
            for (int i = 0; i < seen_count; i++)
                if (!strcmp(seen[i], key)) {
                    fprintf(stderr, "[%s] %s%s%s: '%s' is set more than once; "
                            "the last value wins\n", BRAND_PRODUCT, section,
                            sect_arg[0] ? ":" : "", sect_arg, key);
                    dup_keys++;
                    break;
                }
            if (seen_count < (int)(sizeof(seen) / sizeof(seen[0])) &&
                strlen(key) < sizeof(seen[0]))
                snprintf(seen[seen_count++], sizeof(seen[0]), "%s", key);
        }

        /* ───────── [vlan:N] ───────── */
        if (in_vlan) {
            if      (!strcmp(key,"name"))        snprintf(cur_vlan.name, VLAN_NAME_LEN, "%s", val);
            else if (!strcmp(key,"description")) snprintf(cur_vlan.description, VLAN_DESC_LEN, "%s", val);
            else if (!strcmp(key,"zone"))        cur_vlan.zone = parse_zone(val);
            else if (!strcmp(key,"subnet"))      cur_vlan.subnet  = parse_ip(val);
            else if (!strcmp(key,"netmask"))     cur_vlan.netmask = parse_ip(val);
            else if (!strcmp(key,"gateway"))     cur_vlan.gateway = parse_ip(val);
            else if (!strcmp(key,"dhcp"))        cur_vlan.dhcp_enabled = yes(val);
            else if (!strcmp(key,"dhcp_start"))  cur_vlan.dhcp_start = parse_ip(val);
            else if (!strcmp(key,"dhcp_end"))    cur_vlan.dhcp_end   = parse_ip(val);
            else if (!strcmp(key,"dns_primary")) cur_vlan.dns_primary = parse_ip(val);
            else if (!strcmp(key,"dns_secondary")) cur_vlan.dns_secondary = parse_ip(val);
            else if (!strcmp(key,"lease_time"))  cur_vlan.lease_time = atoi(val);
            else if (!strcmp(key,"inter_vlan_routing")) cur_vlan.inter_vlan_routing = yes(val);
            else if (!strcmp(key,"internet_access"))    cur_vlan.internet_access = yes(val);
            else if (!strcmp(key,"client_isolation"))   cur_vlan.client_isolation = yes(val);
            else if (!strcmp(key,"dpi"))          cur_vlan.dpi_enabled  = yes(val);
            else if (!strcmp(key,"ips"))          cur_vlan.ips_enabled  = yes(val);
            else if (!strcmp(key,"malware_scan")) cur_vlan.malware_scan = yes(val);
            else if (!strcmp(key,"log_all"))      cur_vlan.log_all      = yes(val);
            else if (!strcmp(key,"captive_portal"))  cur_vlan.captive_portal = yes(val);
            else if (!strcmp(key,"show_block_page")) cur_vlan.show_block_page = yes(val);
            else if (!strcmp(key,"bandwidth_down_mbps")) cur_vlan.bandwidth_down_mbps = atoi(val);
            else if (!strcmp(key,"bandwidth_up_mbps"))   cur_vlan.bandwidth_up_mbps   = atoi(val);
            else if (!strcmp(key,"priority"))     cur_vlan.priority = (uint8_t)atoi(val);
            else if (!strcmp(key,"max_clients"))  cur_vlan.max_clients = atoi(val);
            continue;
        }

        /* ───────── [port:ethX] ───────── */
        if (in_port) {
            if      (!strcmp(key,"label")) snprintf(cur_port.label, VLAN_NAME_LEN, "%s", val);
            else if (!strcmp(key,"mode")) {
                if      (!strcasecmp(val,"trunk"))    cur_port.mode = PORT_MODE_TRUNK;
                else if (!strcasecmp(val,"hybrid"))   cur_port.mode = PORT_MODE_HYBRID;
                else if (!strcasecmp(val,"mirror"))   cur_port.mode = PORT_MODE_MIRROR;
                else if (!strcasecmp(val,"disabled")) cur_port.mode = PORT_MODE_DISABLED;
                else                                  cur_port.mode = PORT_MODE_ACCESS;
            }
            else if (!strcmp(key,"zone")) cur_port.zone = parse_zone(val);
            else if (!strcmp(key,"pvid")) cur_port.pvid = (uint16_t)atoi(val);
            else if (!strcmp(key,"allowed_vlans")) {
                char tmp[256];
                snprintf(tmp, sizeof(tmp), "%s", val);
                char *save = NULL;
                for (char *tok = strtok_r(tmp, ",", &save);
                     tok && cur_port.allowed_count < MAX_VLANS_PER_PORT;
                     tok = strtok_r(NULL, ",", &save)) {
                    cur_port.allowed_vlans[cur_port.allowed_count++] =
                        (uint16_t)atoi(trim(tok));
                }
            }
            else if (!strcmp(key,"tag_native"))      cur_port.tag_native    = yes(val);
            else if (!strcmp(key,"drop_untagged"))   cur_port.drop_untagged = yes(val);
            else if (!strcmp(key,"stp_enabled"))     cur_port.stp_enabled   = yes(val);
            else if (!strcmp(key,"storm_control"))   cur_port.storm_control = yes(val);
            else if (!strcmp(key,"storm_pps_limit")) cur_port.storm_pps_limit = atoi(val);
            else if (!strcmp(key,"enabled"))         cur_port.enabled = yes(val);
            continue;
        }

        /* ───────── [alias:NAME] ───────── */
        if (in_alias) {
            if      (!strcmp(key,"kind") || !strcmp(key,"type"))
                cur_alias.kind = policy_alias_kind_from(val);
            else if (!strcmp(key,"description"))
                snprintf(cur_alias.description, POLICY_DESC_LEN, "%s", val);
            else if (!strcmp(key,"entries")) {
                if (policy_parse_entries(&cur_alias, val) < 0) {
                    fprintf(stderr, "[%s] alias '%s': malformed entries\n",
                            BRAND_PRODUCT, cur_alias.name);
                    cur_alias.count = 0;
                }
            }
            else if (!strcmp(key,"enabled")) cur_alias.enabled = yes(val);
            continue;
        }

        /* ───────── [schedule:NAME] ───────── */
        if (in_sched) {
            if      (!strcmp(key,"description"))
                snprintf(cur_sched.description, POLICY_DESC_LEN, "%s", val);
            else if (!strcmp(key,"days")) {
                if (policy_parse_days(val, &cur_sched.days) != 0)
                    fprintf(stderr, "[%s] schedule '%s': bad day list '%s'\n",
                            BRAND_PRODUCT, cur_sched.name, val);
            }
            else if (!strcmp(key,"start")) {
                if (policy_parse_hhmm(val, &cur_sched.start_min) != 0)
                    fprintf(stderr, "[%s] schedule '%s': bad start time '%s'\n",
                            BRAND_PRODUCT, cur_sched.name, val);
            }
            else if (!strcmp(key,"end")) {
                if (policy_parse_hhmm(val, &cur_sched.end_min) != 0)
                    fprintf(stderr, "[%s] schedule '%s': bad end time '%s'\n",
                            BRAND_PRODUCT, cur_sched.name, val);
            }
            else if (!strcmp(key,"enabled")) cur_sched.enabled = yes(val);
            continue;
        }

        /* ───────── [wireguard:wgN] ───────── */
        if (in_wg) {
            if      (!strcmp(key,"private_key"))
                snprintf(cur_wg.private_key, WG_KEY_B64_LEN, "%s", val);
            else if (!strcmp(key,"listen_port")) cur_wg.listen_port = (uint16_t)atoi(val);
            else if (!strcmp(key,"address"))     cur_wg.address = parse_ip(val);
            else if (!strcmp(key,"netmask"))     cur_wg.netmask = parse_ip(val);
            else if (!strcmp(key,"mtu"))         cur_wg.mtu = atoi(val);
            else if (!strcmp(key,"zone"))        cur_wg.zone = parse_zone(val);
            else if (!strcmp(key,"dns"))         cur_wg.dns = parse_ip(val);
            else if (!strcmp(key,"enabled"))     cur_wg.enabled = yes(val);
            else if (!strcmp(key,"description"))
                snprintf(cur_wg.description, VLAN_DESC_LEN, "%s", val);
            continue;
        }

        /* ───────── [wgpeer:NAME] ───────── */
        if (in_peer) {
            if      (!strcmp(key,"interface"))
                snprintf(cur_peer.ifname, IFNAME_LEN, "%s", val);
            else if (!strcmp(key,"public_key"))
                snprintf(cur_peer.public_key, WG_KEY_B64_LEN, "%s", val);
            else if (!strcmp(key,"preshared_key"))
                snprintf(cur_peer.preshared_key, WG_KEY_B64_LEN, "%s", val);
            else if (!strcmp(key,"allowed_ips")) {
                char tmp[1024];
                snprintf(tmp, sizeof(tmp), "%s", val);
                char *save = NULL;
                cur_peer.allowed_count = 0;
                for (char *tok = strtok_r(tmp, ",", &save);
                     tok && cur_peer.allowed_count < WG_ALLOWED_MAX;
                     tok = strtok_r(NULL, ",", &save)) {
                    uint32_t a = 0, m = 0;
                    fx_parse_cidr(trim(tok), &a, &m);
                    if (!a && !m) continue;    /* "any" is not a peer route */
                    cur_peer.allowed[cur_peer.allowed_count].ip   = a;
                    cur_peer.allowed[cur_peer.allowed_count].mask = m;
                    cur_peer.allowed_count++;
                }
            }
            else if (!strcmp(key,"endpoint")) {
                /* host:port; split on the last colon so a bare host works. */
                char hostbuf[VPN_HOST_LEN];
                snprintf(hostbuf, sizeof(hostbuf), "%s", val);
                char *colon = strrchr(hostbuf, ':');
                if (colon) {
                    *colon = '\0';
                    cur_peer.endpoint_port = (uint16_t)atoi(colon + 1);
                }
                snprintf(cur_peer.endpoint_host, VPN_HOST_LEN, "%s", hostbuf);
                if (!cur_peer.endpoint_port) cur_peer.endpoint_port = 51820;
            }
            else if (!strcmp(key,"keepalive"))   cur_peer.keepalive = atoi(val);
            else if (!strcmp(key,"zone"))        cur_peer.zone = parse_zone(val);
            else if (!strcmp(key,"enabled"))     cur_peer.enabled = yes(val);
            else if (!strcmp(key,"description"))
                snprintf(cur_peer.description, VLAN_DESC_LEN, "%s", val);
            continue;
        }

        /* ───────── [ipsec:NAME] ───────── */
        if (in_tun) {
            if      (!strcmp(key,"remote_host"))
                snprintf(cur_tun.remote_host, VPN_HOST_LEN, "%s", val);
            else if (!strcmp(key,"local_id"))
                snprintf(cur_tun.local_id, VPN_HOST_LEN, "%s", val);
            else if (!strcmp(key,"remote_id"))
                snprintf(cur_tun.remote_id, VPN_HOST_LEN, "%s", val);
            else if (!strcmp(key,"local_subnet"))
                fx_parse_cidr(val, &cur_tun.local_subnet, &cur_tun.local_mask);
            else if (!strcmp(key,"remote_subnet"))
                fx_parse_cidr(val, &cur_tun.remote_subnet, &cur_tun.remote_mask);
            else if (!strcmp(key,"psk"))
                snprintf(cur_tun.psk, VPN_SECRET_LEN, "%s", val);
            else if (!strcmp(key,"version"))
                cur_tun.version = !strcasecmp(val, "ikev1") ? IKE_V1 : IKE_V2;
            else if (!strcmp(key,"ike_proposal"))
                snprintf(cur_tun.ike_proposal, VPN_PROPOSAL_LEN, "%s", val);
            else if (!strcmp(key,"esp_proposal"))
                snprintf(cur_tun.esp_proposal, VPN_PROPOSAL_LEN, "%s", val);
            else if (!strcmp(key,"ike_lifetime")) cur_tun.ike_lifetime = atoi(val);
            else if (!strcmp(key,"esp_lifetime")) cur_tun.esp_lifetime = atoi(val);
            else if (!strcmp(key,"dpd"))          cur_tun.dpd = yes(val);
            else if (!strcmp(key,"dpd_delay"))    cur_tun.dpd_delay = atoi(val);
            else if (!strcmp(key,"zone"))         cur_tun.zone = parse_zone(val);
            else if (!strcmp(key,"enabled"))      cur_tun.enabled = yes(val);
            else if (!strcmp(key,"description"))
                snprintf(cur_tun.description, VLAN_DESC_LEN, "%s", val);
            continue;
        }

        /* ───────── [wan:N] ───────── */
        if (in_wan) {
            if      (!strcmp(key,"interface")) snprintf(cur_wan.ifname, IFNAME_LEN, "%s", val);
            else if (!strcmp(key,"mode")) {
                if      (!strcasecmp(val,"static"))   cur_wan.mode = WAN_STATIC;
                else if (!strcasecmp(val,"pppoe"))    cur_wan.mode = WAN_PPPOE;
                else if (!strcasecmp(val,"disabled")) cur_wan.mode = WAN_DISABLED;
                else                                  cur_wan.mode = WAN_DHCP;
            }
            else if (!strcmp(key,"ip"))       cur_wan.ip      = parse_ip(val);
            else if (!strcmp(key,"netmask"))  cur_wan.netmask = parse_ip(val);
            else if (!strcmp(key,"gateway"))  cur_wan.gateway = parse_ip(val);
            else if (!strcmp(key,"dns1"))     cur_wan.dns1    = parse_ip(val);
            else if (!strcmp(key,"dns2"))     cur_wan.dns2    = parse_ip(val);
            else if (!strcmp(key,"mtu"))      cur_wan.mtu     = atoi(val);
            else if (!strcmp(key,"nat"))      cur_wan.nat_enabled = yes(val);
            else if (!strcmp(key,"block_private_in")) cur_wan.block_private_in = yes(val);
            else if (!strcmp(key,"block_bogons"))     cur_wan.block_bogons = yes(val);
            else if (!strcmp(key,"respond_to_ping"))  cur_wan.respond_to_ping = yes(val);
            else if (!strcmp(key,"upnp"))      cur_wan.upnp_enabled = yes(val);
            else if (!strcmp(key,"is_backup")) cur_wan.is_backup = yes(val);
            else if (!strcmp(key,"priority"))  cur_wan.failover_priority = atoi(val);
            else if (!strcmp(key,"monitor_ip"))
                snprintf(cur_wan.monitor_ip, INET_ADDRSTRLEN, "%s", val);
            else if (!strcmp(key,"pppoe_user"))
                snprintf(cur_wan.pppoe_user, sizeof(cur_wan.pppoe_user), "%s", val);
            else if (!strcmp(key,"pppoe_pass"))
                snprintf(cur_wan.pppoe_pass, sizeof(cur_wan.pppoe_pass), "%s", val);
            continue;
        }

        /* ───────── [zones] ───────── */
        if (!strcmp(section, "zones") && !strcmp(key, "zone_policy")) {
            char f[16], t[16], a[16];
            if (sscanf(val, "%15s %15s %15s", f, t, a) == 3)
                vlan_set_zone_policy(v, parse_zone(f), parse_zone(t), parse_action(a));
            continue;
        }

        /* ───────── [acl] ─────────
         * rule = <svlan> -> <dvlan> <proto> <port> <ACTION> <prio> "desc"
         */
        if (!strcmp(section, "acl") && !strcmp(key, "rule")) {
            char svl[8], arrow[4], dvl[8], proto[8], port[16], act[16];
            char desc[128] = "";
            int prio = 100;

            int got = sscanf(val, "%7s %3s %7s %7s %15s %15s %d \"%127[^\"]\"",
                             svl, arrow, dvl, proto, port, act, &prio, desc);
            if (got < 6) { skipped_acl++; continue; }

            ivr_rule_t r;
            memset(&r, 0, sizeof(r));
            r.src_vlan = (strcmp(svl,"*") == 0) ? 0 : (uint16_t)atoi(svl);
            r.dst_vlan = (strcmp(dvl,"*") == 0) ? 0 : (uint16_t)atoi(dvl);

            if      (!strcasecmp(proto,"tcp"))  r.protocol = 6;
            else if (!strcasecmp(proto,"udp"))  r.protocol = 17;
            else if (!strcasecmp(proto,"icmp")) r.protocol = 1;
            else                                r.protocol = 0;

            if (strcmp(port, "*") != 0) {
                char *dash = strchr(port, '-');
                if (dash) {
                    *dash = '\0';
                    r.dst_port_start = (uint16_t)atoi(port);
                    r.dst_port_end   = (uint16_t)atoi(dash + 1);
                } else {
                    r.dst_port_start = r.dst_port_end = (uint16_t)atoi(port);
                }
            }

            r.action   = parse_action(act);
            r.priority = (got >= 7) ? prio : 100;
            snprintf(r.description, VLAN_DESC_LEN, "%s", desc);

            /* A $NAME in the port field is an alias reference rather than a
             * literal port or range. */
            if (port[0] == '$') {
                copy_ref(r.port_alias, POLICY_NAME_LEN, port + 1, "port alias");
                r.dst_port_start = r.dst_port_end = 0;
            }

            /* Optional trailing matches written by config_write.c. A config
             * without these parses exactly as it did before. Each of src= and
             * dst= takes either a CIDR or a $ALIAS. */
            char ref[80];
            if (parse_opt_token(val, "src=", ref, sizeof(ref))) {
                if (ref[0] == '$') copy_ref(r.src_alias, POLICY_NAME_LEN, ref + 1, "source alias");
                else               fx_parse_cidr(ref, &r.src_ip, &r.src_mask);
            }
            if (parse_opt_token(val, "dst=", ref, sizeof(ref))) {
                if (ref[0] == '$') copy_ref(r.dst_alias, POLICY_NAME_LEN, ref + 1, "destination alias");
                else               fx_parse_cidr(ref, &r.dst_ip, &r.dst_mask);
            }
            if (parse_opt_token(val, "sched=", ref, sizeof(ref)))
                copy_ref(r.schedule, POLICY_NAME_LEN, ref, "schedule");

            ivr_add_rule(v, &r);
            continue;
        }

        /* ───────── [forward] ───────── */
        if (!strcmp(section, "forward") && !strcmp(key, "fwd")) {
            char name[32], proto[8], iip[48], vlanbuf[8], srcres[48], logs[8];
            int wport = 0, iport = 0;

            int got = sscanf(val, "%31s %7s %d %47s %d %7s %47s %7s",
                             name, proto, &wport, iip, &iport, vlanbuf, srcres, logs);
            if (got < 5) continue;

            port_forward_t f;
            memset(&f, 0, sizeof(f));
            snprintf(f.name, VLAN_NAME_LEN, "%s", name);
            f.protocol       = (!strcasecmp(proto,"udp")) ? 17 : 6;
            f.wan_port_start = f.wan_port_end = (uint16_t)wport;
            f.internal_ip    = parse_ip(iip);
            f.internal_port  = (uint16_t)iport;
            f.dst_vlan       = (got >= 6) ? (uint16_t)atoi(vlanbuf) : 0;
            if (got >= 7) fx_parse_cidr(srcres, &f.source_restrict, &f.source_mask);
            f.log_hits       = (got >= 8) ? yes(logs) : true;
            snprintf(f.description, VLAN_DESC_LEN, "Published service: %s", name);
            netconf_add_forward(n, &f);
            continue;
        }

        /* ───────── [route] ─────────
         * route = <dest/cidr> <gateway> [iface] [metric] ["desc"]
         */
        if (!strcmp(section, "route") && !strcmp(key, "route")) {
            char dest[64], gw[48], iface[32] = "", desc[128] = "";
            int metric = 1;

            int got = sscanf(val, "%63s %47s %31s %d \"%127[^\"]\"",
                             dest, gw, iface, &metric, desc);
            if (got < 2) { skipped_route++; continue; }

            static_route_t rt;
            memset(&rt, 0, sizeof(rt));
            fx_parse_cidr(dest, &rt.dest, &rt.mask);
            rt.gateway = parse_ip(gw);
            if (!rt.gateway) { skipped_route++; continue; }

            if (got >= 3 && strcmp(iface, "-") != 0)
                snprintf(rt.ifname, IFNAME_LEN, "%s", iface);
            rt.metric = (got >= 4 && metric > 0) ? metric : 1;
            snprintf(rt.description, VLAN_DESC_LEN, "%s", desc);

            netconf_add_route(n, &rt);
            continue;
        }

        /* ───────── [monitor] ───────── */
        if (!strcmp(section, "monitor")) {
            if      (!strcmp(key,"interval"))       n->monitor_interval   = atoi(val);
            else if (!strcmp(key,"timeout_ms"))     n->monitor_timeout_ms = atoi(val);
            else if (!strcmp(key,"fail_threshold")) n->monitor_fail       = atoi(val);
            else if (!strcmp(key,"ok_threshold"))   n->monitor_ok         = atoi(val);
            continue;
        }

        /* ───────── [shaping] ───────── */
        if (!strcmp(section, "shaping")) {
            shaper_cfg_t *sc = &n->shaping;
            if      (!strcmp(key,"enabled"))         sc->enabled = yes(val);
            else if (!strcmp(key,"wan_up_mbps"))     sc->wan_up_mbps = atoi(val);
            else if (!strcmp(key,"wan_down_mbps"))   sc->wan_down_mbps = atoi(val);
            else if (!strcmp(key,"qdisc"))           sc->qdisc = qdisc_from(val);
            else if (!strcmp(key,"codel_target_ms")) sc->codel_target_ms = atoi(val);
            else if (!strcmp(key,"codel_interval_ms")) sc->codel_interval_ms = atoi(val);
            else if (!strcmp(key,"ecn"))             sc->ecn = yes(val);
            else if (!strcmp(key,"ingress_shaping")) sc->ingress_shaping = yes(val);
            continue;
        }

        /* ───────── [portal] ───────── */
        if (!strcmp(section, "portal")) {
            portal_cfg_t *pc = &n->portal;
            if      (!strcmp(key,"enabled"))         pc->enabled = yes(val);
            else if (!strcmp(key,"auth"))            pc->auth = portal_auth_from(val);
            else if (!strcmp(key,"session_minutes")) pc->session_minutes = atoi(val);
            else if (!strcmp(key,"idle_minutes"))    pc->idle_minutes = atoi(val);
            else if (!strcmp(key,"terms"))
                snprintf(pc->terms, PORTAL_TERMS_LEN, "%s", val);
            else if (!strcmp(key,"radius_host"))
                snprintf(pc->radius_host, PORTAL_HOST_LEN, "%s", val);
            else if (!strcmp(key,"radius_port"))     pc->radius_port = (uint16_t)atoi(val);
            else if (!strcmp(key,"radius_secret"))
                snprintf(pc->radius_secret, PORTAL_SECRET_LEN, "%s", val);
            else if (!strcmp(key,"nas_id"))
                snprintf(pc->nas_id, PORTAL_USER_LEN, "%s", val);
            else if (!strcmp(key,"radius_timeout_ms")) pc->radius_timeout_ms = atoi(val);
            else if (!strcmp(key,"radius_retries"))    pc->radius_retries = atoi(val);
            continue;
        }

        /* ───────── [feed:NAME] ───────── */
        if (in_feed) {
            if      (!strcmp(key,"url"))
                snprintf(cur_feed.url, FEED_URL_LEN, "%s", val);
            else if (!strcmp(key,"kind") || !strcmp(key,"type"))
                cur_feed.kind = feed_kind_from(val);
            else if (!strcmp(key,"refresh") || !strcmp(key,"refresh_minutes"))
                cur_feed.refresh_minutes = atoi(val);
            else if (!strcmp(key,"enabled")) cur_feed.enabled = yes(val);
            continue;
        }

        /* ───────── [threat] ───────── */
        if (!strcmp(section, "threat")) {
            threat_cfg_t *tc = &n->threat;
            if      (!strcmp(key,"enabled"))       tc->enabled = yes(val);
            else if (!strcmp(key,"inline"))        tc->inline_mode = yes(val);
            else if (!strcmp(key,"rules"))
                snprintf(tc->rules_path, sizeof(tc->rules_path), "%s", val);
            else if (!strcmp(key,"feeds_enabled")) tc->feeds_enabled = yes(val);
            continue;
        }

        /* ───────── [console] ───────── */
        if (!strcmp(section, "console")) {
            if      (!strcmp(key,"port")) n->console_port = atoi(val);
            else if (!strcmp(key,"bind"))
                snprintf(n->console_bind, sizeof(n->console_bind), "%s", val);
            else if (!strcmp(key,"tls")) {
                n->console_tls     = yes(val);
                n->console_tls_set = true;
            }
            else if (!strcmp(key,"tls_cert"))
                snprintf(n->console_tls_cert, sizeof(n->console_tls_cert), "%s", val);
            else if (!strcmp(key,"tls_key"))
                snprintf(n->console_tls_key, sizeof(n->console_tls_key), "%s", val);
            continue;
        }

        /* ───────── [malware] ───────── */
        if (!strcmp(section, "malware")) {
            mw_cfg_t *mc = &n->malware;
            if      (!strcmp(key,"enabled"))      mc->enabled = yes(val);
            else if (!strcmp(key,"block"))        mc->block = yes(val);
            else if (!strcmp(key,"scan_uploads")) mc->scan_uploads = yes(val);
            else if (!strcmp(key,"max_object_kb"))mc->max_object_kb = atoi(val);
            else if (!strcmp(key,"flow_idle"))    mc->flow_idle_seconds = atoi(val);
            else if (!strcmp(key,"database"))
                snprintf(mc->db_path, sizeof(mc->db_path), "%s", val);
            continue;
        }

        /* ───────── [airgap] ───────── */
        if (!strcmp(section, "airgap")) {
            ag_cfg_t *ac = &n->airgap;
            if (!strcmp(key,"mode")) {
                ag_mode_t m;
                /* An unknown mode is NOT quietly treated as "connected":
                 * a typo in the one setting that isolates the appliance
                 * must not be the thing that silently connects it. */
                if (airgap_mode_from_name(val, &m)) ac->mode = m;
                else fprintf(stderr,
                        "[config] airgap mode '%s' is not recognised; "
                        "leaving it at %s\n", val, airgap_mode_name(ac->mode));
            }
            else if (!strcmp(key,"require_time_sync")) ac->require_time_sync = yes(val);
            else if (!strcmp(key,"log_denied"))        ac->log_denied = yes(val);
            else if (!strcmp(key,"window")) {
                /* window = name,days,HH:MM,HH:MM,in,out
                 * days is a 7-character mask starting Sunday, "-MTWTF-"
                 * style, so it reads the way a weekly schedule is drawn. */
                if (n->airgap_window_count < AG_MAX_WINDOWS) {
                    char nm[AG_NAME_LEN] = "window", days[16] = "";
                    int sh = 0, sm = 0, eh = 0, em = 0, ain = 1, aout = 1;
                    if (sscanf(val, "%47[^,],%15[^,],%d:%d,%d:%d,%d,%d",
                               nm, days, &sh, &sm, &eh, &em, &ain, &aout) >= 6) {
                        uint8_t mask = 0;
                        for (int d = 0; d < 7 && days[d]; d++)
                            if (days[d] != '-' && days[d] != '.') mask |= (uint8_t)(1u << d);
                        ag_window_t *w = &n->airgap_windows[n->airgap_window_count++];
                        memset(w, 0, sizeof(*w));
                        w->used      = true;
                        w->days      = mask;
                        w->start_min = (uint16_t)(sh * 60 + sm);
                        w->end_min   = (uint16_t)(eh * 60 + em);
                        w->allow_in  = ain != 0;
                        w->allow_out = aout != 0;
                        snprintf(w->name, sizeof(w->name), "%s", nm);
                    }
                }
            }
            continue;
        }

        /* ───────── [response] ───────── */
        if (!strcmp(section, "response")) {
            response_cfg_t *rc = &n->response;
            if      (!strcmp(key,"enabled"))           rc->enabled = yes(val);
            else if (!strcmp(key,"threshold"))         rc->threshold = atoi(val);
            else if (!strcmp(key,"block_minutes"))     rc->block_minutes = atoi(val);
            else if (!strcmp(key,"escalate"))          rc->escalate = yes(val);
            else if (!strcmp(key,"max_block_minutes")) rc->max_block_minutes = atoi(val);
            else if (!strcmp(key,"decay_minutes"))     rc->decay_minutes = atoi(val);
            else if (!strcmp(key,"quarantine"))        rc->quarantine = yes(val);
            else if (!strcmp(key,"notify"))            rc->notify = yes(val);
            continue;
        }

        /* ───────── [ha] ───────── */
        if (!strcmp(section, "ha")) {
            ha_cfg_t *hc = &n->ha;
            if      (!strcmp(key,"enabled"))        hc->enabled = yes(val);
            else if (!strcmp(key,"role"))           hc->role = ha_role_from(val);
            else if (!strcmp(key,"peer_address"))
                snprintf(hc->peer_address, HA_ADDR_LEN, "%s", val);
            else if (!strcmp(key,"sync_interface"))
                snprintf(hc->sync_interface, IFNAME_LEN, "%s", val);
            else if (!strcmp(key,"sync_address"))
                snprintf(hc->sync_address, HA_ADDR_LEN, "%s", val);
            else if (!strcmp(key,"vrrp_id"))        hc->vrrp_id = atoi(val);
            else if (!strcmp(key,"vrrp_password"))
                snprintf(hc->vrrp_password, HA_VRRP_PASS_LEN, "%s", val);
            else if (!strcmp(key,"priority"))       hc->priority = atoi(val);
            else if (!strcmp(key,"advert_interval")) hc->advert_interval = atoi(val);
            else if (!strcmp(key,"preempt"))        hc->preempt = yes(val);
            else if (!strcmp(key,"conntrack_sync")) hc->conntrack_sync = yes(val);
            else if (!strcmp(key,"conntrack_port")) hc->conntrack_port = atoi(val);
            else if (!strcmp(key,"config_sync"))    hc->config_sync = yes(val);
            else if (!strcmp(key,"config_sync_port")) hc->config_sync_port = atoi(val);
            else if (!strcmp(key,"sync_secret"))
                snprintf(hc->sync_secret, HA_SECRET_LEN, "%s", val);
            continue;
        }

        /* ───────── [telemetry] ───────── */
        if (!strcmp(section, "telemetry")) {
            telemetry_cfg_t *tc = &n->telemetry;
            if      (!strcmp(key,"syslog_host"))
                snprintf(tc->syslog_host, TELEM_HOST_LEN, "%s", val);
            else if (!strcmp(key,"syslog_port"))     tc->syslog_port = (uint16_t)atoi(val);
            else if (!strcmp(key,"syslog_proto"))    tc->syslog_tcp = !strcasecmp(val, "tcp");
            else if (!strcmp(key,"syslog_facility")) tc->syslog_facility = atoi(val);
            else if (!strcmp(key,"syslog_min_severity"))
                tc->syslog_min_severity = atoi(val);
            else if (!strcmp(key,"netflow_host"))
                snprintf(tc->netflow_host, TELEM_HOST_LEN, "%s", val);
            else if (!strcmp(key,"netflow_port"))     tc->netflow_port = (uint16_t)atoi(val);
            else if (!strcmp(key,"netflow_interval")) tc->netflow_interval = atoi(val);
            else if (!strcmp(key,"history_interval")) tc->history_interval = atoi(val);
            continue;
        }

        /* ───────── [blockpage] ───────── */
        if (!strcmp(section, "blockpage")) {
            if      (!strcmp(key,"enabled"))        bp->enabled = yes(val);
            else if (!strcmp(key,"port"))           bp->port = atoi(val);
            else if (!strcmp(key,"org_name"))       snprintf(bp->org_name, sizeof(bp->org_name), "%s", val);
            else if (!strcmp(key,"admin_contact"))  snprintf(bp->admin_contact, sizeof(bp->admin_contact), "%s", val);
            else if (!strcmp(key,"show_technical")) bp->show_technical = yes(val);
            else if (!strcmp(key,"allow_override")) bp->allow_override = yes(val);
            else if (!strcmp(key,"show_logo"))      bp->show_logo = yes(val);
            continue;
        }

        /* ───────── [system] ───────── */
        if (!strcmp(section, "system")) {
            if      (!strcmp(key,"domain"))        snprintf(n->domain, sizeof(n->domain), "%s", val);
            else if (!strcmp(key,"organisation"))  snprintf(bp->org_name, sizeof(bp->org_name), "%s", val);
            else if (!strcmp(key,"admin_contact")) snprintf(bp->admin_contact, sizeof(bp->admin_contact), "%s", val);
            continue;
        }
    }

    FLUSH_VLAN(); FLUSH_PORT(); FLUSH_WAN();
    FLUSH_ALIAS(); FLUSH_SCHED();
    FLUSH_WG(); FLUSH_PEER(); FLUSH_TUN(); FLUSH_FEED();
    fclose(fp);

    if (skipped_vlans)
        fprintf(stderr, "[%s] %d VLAN block(s) rejected (bad id, duplicate or table full)\n",
                BRAND_PRODUCT, skipped_vlans);
    if (skipped_acl)
        fprintf(stderr, "[%s] %d malformed ACL rule(s) ignored\n",
                BRAND_PRODUCT, skipped_acl);
    if (skipped_alias)
        fprintf(stderr, "[%s] %d alias block(s) rejected (duplicate, empty "
                "or table full)\n", BRAND_PRODUCT, skipped_alias);
    if (skipped_sched)
        fprintf(stderr, "[%s] %d schedule block(s) rejected\n",
                BRAND_PRODUCT, skipped_sched);
    if (skipped_route)
        fprintf(stderr, "[%s] %d malformed static route(s) ignored\n",
                BRAND_PRODUCT, skipped_route);
    if (skipped_vpn)
        fprintf(stderr, "[%s] %d VPN block(s) rejected (duplicate, incomplete "
                "or table full)\n", BRAND_PRODUCT, skipped_vpn);
    if (dup_keys)
        fprintf(stderr, "[%s] %d duplicated key(s) in %s\n",
                BRAND_PRODUCT, dup_keys, path);

    printf("[%s] Enterprise config loaded: %d VLANs, %d ports, %d ACLs, "
           "%d WAN links, %d port-forwards\n",
           BRAND_PRODUCT, v->vlan_count, v->port_count, v->ivr_count,
           n->wan_count, n->forward_count);
    if (pol && (pol->alias_count || pol->schedule_count))
        printf("[%s]   policy: %d alias(es), %d schedule(s)\n",
               BRAND_PRODUCT, pol->alias_count, pol->schedule_count);
    if (n->route_count)
        printf("[%s]   routing: %d static route(s)\n",
               BRAND_PRODUCT, n->route_count);
    if (vpn && (vpn->wg_count || vpn->tunnel_count))
        printf("[%s]   vpn: %d WireGuard interface(s), %d peer(s), "
               "%d IPsec tunnel(s)\n", BRAND_PRODUCT,
               vpn->wg_count, vpn->peer_count, vpn->tunnel_count);
    return 0;
}
