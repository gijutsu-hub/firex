#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "netconf.h"
#include "shellcmd.h"
#include "netutil.h"

#define SAFE_IF(w) fx_ifname_safe((w), IFNAME_LEN)

int netconf_init(netconf_ctx_t *n) {
    memset(n, 0, sizeof(*n));
    pthread_mutex_init(&n->lock, NULL);
    snprintf(n->domain, sizeof(n->domain), "firex.local");
    return 0;
}

/* ═══════════ WAN BRING-UP ═══════════ */
int netconf_apply_wan(netconf_ctx_t *n) {
    char cmd[640], abuf[INET_ADDRSTRLEN];

    for (int i = 0; i < n->wan_count; i++) {
        wan_config_t *w = &n->wan[i];
        if (w->mode == WAN_DISABLED) continue;

        if (!SAFE_IF(w->ifname)) {
            fprintf(stderr, "[%s] WAN%d: refusing unsafe interface name\n",
                    BRAND_PRODUCT, i);
            continue;
        }

        printf("[%s] WAN%d (%s) mode=%s\n", BRAND_PRODUCT, i, w->ifname,
               w->mode == WAN_DHCP   ? "DHCP"   :
               w->mode == WAN_STATIC ? "STATIC" : "PPPoE");

        snprintf(cmd, sizeof(cmd), "ip link set %s up", w->ifname);
        fx_run(cmd);

        if (w->mtu > 0) {
            snprintf(cmd, sizeof(cmd), "ip link set %s mtu %d", w->ifname, w->mtu);
            fx_run(cmd);
        }

        switch (w->mode) {
        case WAN_DHCP:
            snprintf(cmd, sizeof(cmd),
                     "dhcpcd -q -t 20 %s 2>/dev/null || udhcpc -i %s -n -q 2>/dev/null",
                     w->ifname, w->ifname);
            fx_try(cmd);
            break;

        case WAN_STATIC: {
            int bits = fx_netmask_to_cidr(w->netmask);

            snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s 2>/dev/null",
                     fx_ip_str(w->ip, abuf, sizeof(abuf)), bits, w->ifname);
            fx_try(cmd);

            snprintf(cmd, sizeof(cmd),
                     "ip route add default via %s dev %s metric %d 2>/dev/null",
                     fx_ip_str(w->gateway, abuf, sizeof(abuf)), w->ifname,
                     w->is_backup ? 200 : 100);
            fx_try(cmd);

            FILE *r = fopen("/etc/resolv.conf", "w");
            if (r) {
                if (w->dns1)
                    fprintf(r, "nameserver %s\n",
                            fx_ip_str(w->dns1, abuf, sizeof(abuf)));
                if (w->dns2)
                    fprintf(r, "nameserver %s\n",
                            fx_ip_str(w->dns2, abuf, sizeof(abuf)));
                fprintf(r, "search %s\n", n->domain);
                fclose(r);
            } else {
                fprintf(stderr, "[%s] could not write /etc/resolv.conf\n",
                        BRAND_PRODUCT);
            }
            break;
        }

        case WAN_PPPOE: {
            FILE *p = fopen("/etc/ppp/pppoe.conf", "w");
            if (p) {
                fprintf(p, "ETH=%s\nUSER=%s\nDEMAND=no\nDNSTYPE=SERVER\n"
                           "PEERDNS=yes\nDEFAULTROUTE=yes\n",
                        w->ifname, w->pppoe_user);
                fclose(p);
            }
            /* Create the secrets file private before the password goes in. */
            int fd_ok = 0;
            FILE *s = fopen("/etc/ppp/pap-secrets", "w");
            if (s) {
                fd_ok = (chmod("/etc/ppp/pap-secrets", 0600) == 0);
                fprintf(s, "\"%s\" * \"%s\"\n", w->pppoe_user, w->pppoe_pass);
                fclose(s);
                if (!fd_ok)
                    fprintf(stderr, "[%s] WARNING: could not restrict "
                            "/etc/ppp/pap-secrets to mode 0600\n", BRAND_PRODUCT);
            }
            fx_try("pppoe-start 2>/dev/null &");
            break;
        }
        default:
            break;
        }

        /* ── WAN ingress hardening ── */
        if (w->block_private_in) {
            static const char *bogons[] = {
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", NULL };
            for (int b = 0; bogons[b]; b++) {
                snprintf(cmd, sizeof(cmd),
                    "iptables -A INPUT -i %s -s %s -j DROP", w->ifname, bogons[b]);
                fx_run(cmd);
                snprintf(cmd, sizeof(cmd),
                    "iptables -A FORWARD -i %s -s %s -j DROP", w->ifname, bogons[b]);
                fx_run(cmd);
            }
        }

        if (w->block_bogons) {
            static const char *bg[] = { "0.0.0.0/8", "192.0.2.0/24",
                                        "198.18.0.0/15", "224.0.0.0/4",
                                        "240.0.0.0/4", NULL };
            for (int b = 0; bg[b]; b++) {
                snprintf(cmd, sizeof(cmd),
                    "iptables -A INPUT -i %s -s %s -j DROP", w->ifname, bg[b]);
                fx_run(cmd);
            }
        }

        if (!w->respond_to_ping) {
            snprintf(cmd, sizeof(cmd),
                "iptables -A INPUT -i %s -p icmp --icmp-type echo-request -j DROP",
                w->ifname);
            fx_run(cmd);
        }

        /* Anti-spoof / state tracking */
        snprintf(cmd, sizeof(cmd),
            "iptables -A INPUT -i %s -m conntrack --ctstate INVALID -j DROP",
            w->ifname);
        fx_run(cmd);
        snprintf(cmd, sizeof(cmd),
            "iptables -A INPUT -i %s -p tcp ! --syn -m conntrack --ctstate NEW -j DROP",
            w->ifname);
        fx_run(cmd);
    }
    return 0;
}

/* ═══════════ NAT / MASQUERADE ═══════════ */
int netconf_apply_nat(netconf_ctx_t *n, vlan_ctx_t *v) {
    char cmd[640], abuf[INET_ADDRSTRLEN];
    printf("[%s] Applying NAT policy...\n", BRAND_PRODUCT);

    fx_try("iptables -t nat -N FIREX_NAT 2>/dev/null");
    fx_run("iptables -t nat -F FIREX_NAT");
    fx_try("iptables -t nat -D POSTROUTING -j FIREX_NAT 2>/dev/null");
    fx_run("iptables -t nat -A POSTROUTING -j FIREX_NAT");

    for (int i = 0; i < n->wan_count; i++) {
        wan_config_t *w = &n->wan[i];
        if (!w->nat_enabled || w->mode == WAN_DISABLED) continue;
        if (!SAFE_IF(w->ifname)) continue;

        /* Only NAT the VLANs explicitly permitted internet access. */
        for (int j = 0; j < v->vlan_count; j++) {
            vlan_config_t *vl = &v->vlans[j];
            if (!vl->enabled || !vl->internet_access) continue;

            int bits = fx_netmask_to_cidr(vl->netmask);
            snprintf(cmd, sizeof(cmd),
                "iptables -t nat -A FIREX_NAT -s %s/%d -o %s -j MASQUERADE",
                fx_ip_str(vl->subnet, abuf, sizeof(abuf)), bits, w->ifname);
            fx_run(cmd);

            printf("  [NAT] VLAN %u (%s) -> %s\n", vl->vlan_id, vl->name, w->ifname);
        }
    }

    /* Hairpin / NAT reflection for internal access to published services */
    if (n->hairpin_nat)
        fx_try("iptables -t nat -A FIREX_NAT -m conntrack "
               "--ctstate DNAT -j MASQUERADE 2>/dev/null");

    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (f) { fputc('1', f); fclose(f); }
    else fprintf(stderr, "[%s] could not enable ip_forward\n", BRAND_PRODUCT);

    return 0;
}

/* ═══════════ PORT FORWARDING (DNAT) ═══════════ */
int netconf_add_route(netconf_ctx_t *n, static_route_t *r) {
    pthread_mutex_lock(&n->lock);
    if (n->route_count >= MAX_STATIC_ROUTES) {
        pthread_mutex_unlock(&n->lock);
        return -1;
    }
    r->enabled = true;
    if (r->metric <= 0) r->metric = 1;
    n->routes[n->route_count++] = *r;
    int id = n->route_count - 1;
    pthread_mutex_unlock(&n->lock);
    return id;
}

int netconf_apply_routes(netconf_ctx_t *n) {
    if (!n->route_count) return 0;

    char cmd[640], dbuf[INET_ADDRSTRLEN], gbuf[INET_ADDRSTRLEN];
    printf("[%s] Installing static routes...\n", BRAND_PRODUCT);

    for (int i = 0; i < n->route_count; i++) {
        static_route_t *r = &n->routes[i];
        if (!r->enabled) continue;
        if (r->ifname[0] && !SAFE_IF(r->ifname)) {
            fprintf(stderr, "[%s] route %d: refusing unsafe interface name\n",
                    BRAND_PRODUCT, i);
            continue;
        }

        int bits = fx_netmask_to_cidr(r->mask);
        fx_ip_str(r->dest,    dbuf, sizeof(dbuf));
        fx_ip_str(r->gateway, gbuf, sizeof(gbuf));

        char dev[64] = "";
        if (r->ifname[0]) snprintf(dev, sizeof(dev), " dev %s", r->ifname);

        /* Replace rather than stack: a re-apply after an edit must not leave
         * the previous version of the route behind. */
        snprintf(cmd, sizeof(cmd), "ip route del %s/%d 2>/dev/null", dbuf, bits);
        fx_try(cmd);

        snprintf(cmd, sizeof(cmd), "ip route add %s/%d via %s%s metric %d",
                 dbuf, bits, gbuf, dev, r->metric);
        fx_run(cmd);

        printf("  [ROUTE] %s/%d via %s%s metric %d\n",
               dbuf, bits, gbuf, dev, r->metric);
    }
    return 0;
}

int netconf_add_forward(netconf_ctx_t *n, port_forward_t *f) {
    pthread_mutex_lock(&n->lock);
    if (n->forward_count >= MAX_PORT_FORWARDS) {
        pthread_mutex_unlock(&n->lock);
        return -1;
    }
    f->id = n->forward_count;
    f->enabled = true;
    n->forwards[n->forward_count++] = *f;
    int id = f->id;
    pthread_mutex_unlock(&n->lock);
    return id;
}

int netconf_apply_forwards(netconf_ctx_t *n) {
    char cmd[768], intip[INET_ADDRSTRLEN], sbuf[INET_ADDRSTRLEN];

    fx_try("iptables -t nat -N FIREX_DNAT 2>/dev/null");
    fx_run("iptables -t nat -F FIREX_DNAT");
    fx_try("iptables -t nat -D PREROUTING -j FIREX_DNAT 2>/dev/null");
    fx_run("iptables -t nat -A PREROUTING -j FIREX_DNAT");

    for (int i = 0; i < n->forward_count; i++) {
        port_forward_t *f = &n->forwards[i];
        if (!f->enabled) continue;

        const char *proto = (f->protocol == 17) ? "udp" : "tcp";
        fx_ip_str(f->internal_ip, intip, sizeof(intip));

        char src_clause[96] = "";
        if (f->source_restrict) {
            snprintf(src_clause, sizeof(src_clause), "-s %s/%d",
                     fx_ip_str(f->source_restrict, sbuf, sizeof(sbuf)),
                     fx_netmask_to_cidr(f->source_mask));
        }

        char portspec[32];
        if (f->wan_port_end && f->wan_port_end != f->wan_port_start)
            snprintf(portspec, sizeof(portspec), "%u:%u",
                     f->wan_port_start, f->wan_port_end);
        else
            snprintf(portspec, sizeof(portspec), "%u", f->wan_port_start);

        for (int w = 0; w < n->wan_count; w++) {
            if (!SAFE_IF(n->wan[w].ifname)) continue;
            snprintf(cmd, sizeof(cmd),
                "iptables -t nat -A FIREX_DNAT -i %s %s -p %s --dport %s "
                "-j DNAT --to-destination %s:%u",
                n->wan[w].ifname, src_clause, proto, portspec,
                intip, f->internal_port);
            fx_run(cmd);
        }

        /* Matching FORWARD accept */
        snprintf(cmd, sizeof(cmd),
            "iptables -I FIREX_FWD -p %s -d %s --dport %u "
            "-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",
            proto, intip, f->internal_port);
        fx_run(cmd);

        if (f->log_hits) {
            snprintf(cmd, sizeof(cmd),
                "iptables -I FIREX_FWD -p %s -d %s --dport %u -j LOG "
                "--log-prefix \"%s-FWD-%d: \" --log-level 6",
                proto, intip, f->internal_port, BRAND_PRODUCT, f->id);
            fx_run(cmd);
        }

        printf("  [FWD %02d] WAN:%s/%s -> %s:%u  (%s)\n",
               f->id, portspec, proto, intip, f->internal_port, f->name);
    }
    return 0;
}

/* ═══════════ DHCP SERVER CONFIG GENERATION ═══════════ */
int netconf_generate_dhcp(netconf_ctx_t *n, vlan_ctx_t *v, const char *out) {
    FILE *fp = fopen(out, "w");
    if (!fp) {
        fprintf(stderr, "[%s] cannot write %s\n", BRAND_PRODUCT, out);
        return -1;
    }

    fprintf(fp,
        "# ================================================\n"
        "#  %s - %s\n"
        "#  DHCP server configuration (auto-generated)\n"
        "# ================================================\n\n"
        "port=53\n"
        "domain-needed\n"
        "bogus-priv\n"
        "no-resolv\n"
        "server=1.1.1.1\n"
        "server=9.9.9.9\n"
        "cache-size=2000\n"
        "domain=%s\n"
        "local=/%s/\n"
        "expand-hosts\n"
        "dhcp-authoritative\n"
        "log-dhcp\n\n",
        BRAND_FULL, BRAND_TAGLINE, n->domain, n->domain);

    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *vl = &v->vlans[i];
        if (!vl->enabled || !vl->dhcp_enabled) continue;

        char sbuf[INET_ADDRSTRLEN], ebuf[INET_ADDRSTRLEN], mbuf[INET_ADDRSTRLEN];
        char gbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];

        fx_ip_str(vl->dhcp_start, sbuf, sizeof(sbuf));
        fx_ip_str(vl->dhcp_end,   ebuf, sizeof(ebuf));
        fx_ip_str(vl->netmask,    mbuf, sizeof(mbuf));
        fx_ip_str(vl->gateway,    gbuf, sizeof(gbuf));
        fx_ip_str(vl->dns_primary ? vl->dns_primary : vl->gateway,
                  dbuf, sizeof(dbuf));

        fprintf(fp,
            "# -- VLAN %u : %s (%s zone) --\n"
            "dhcp-range=set:vlan%u,%s,%s,%s,%dh\n"
            "dhcp-option=tag:vlan%u,option:router,%s\n"
            "dhcp-option=tag:vlan%u,option:dns-server,%s\n"
            "dhcp-option=tag:vlan%u,option:domain-name,%s.%s\n",
            vl->vlan_id, vl->name, zone_name(vl->zone),
            vl->vlan_id, sbuf, ebuf, mbuf, vl->lease_time / 3600,
            vl->vlan_id, gbuf,
            vl->vlan_id, dbuf,
            vl->vlan_id, vl->name, n->domain);

        if (vl->max_clients > 0)
            fprintf(fp, "dhcp-lease-max=%d\n", vl->max_clients);

        if (vl->captive_portal)
            fprintf(fp, "dhcp-option=tag:vlan%u,114,\"http://%s:8080/portal\"\n",
                    vl->vlan_id, gbuf);

        fprintf(fp, "\n");
    }

    if (n->reservation_count) {
        fprintf(fp, "# -- Static reservations --\n");
        for (int i = 0; i < n->reservation_count; i++) {
            dhcp_reservation_t *r = &n->reservations[i];
            if (!r->enabled) continue;
            char abuf[INET_ADDRSTRLEN];
            fprintf(fp, "dhcp-host=%02x:%02x:%02x:%02x:%02x:%02x,%s,%s  # %s\n",
                    r->mac[0], r->mac[1], r->mac[2],
                    r->mac[3], r->mac[4], r->mac[5],
                    fx_ip_str(r->ip, abuf, sizeof(abuf)), r->hostname, r->note);
        }
    }

    fclose(fp);
    printf("[%s] DHCP config written -> %s\n", BRAND_PRODUCT, out);
    return 0;
}

void netconf_shutdown(netconf_ctx_t *n) {
    pthread_mutex_destroy(&n->lock);
}
