/*
 * firexd - headless FireX appliance daemon.
 *
 * This is the entry point the boot scripts use. It loads the enterprise
 * config, provisions the network (WAN, VLANs, NAT, published services, DHCP),
 * starts the block-page portal and the packet engine, then runs until it is
 * signalled.
 *
 * The GTK console (flamewall) remains a separate binary for interactive use;
 * both share the same engine objects.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <termios.h>
#include <time.h>
#include <arpa/inet.h>

#include "firewall.h"
#include "engine.h"
#include "inspect.h"
#include "enterprise.h"
#include "webui.h"
#include "reload.h"
#include "config_write.h"
#include "configstore.h"
#include "policy.h"
#include "gwmon.h"
#include "vpn.h"
#include "histstats.h"
#include "capture.h"
#include "telemetry.h"
#include "conntrack.h"
#include "shaper.h"
#include "portal.h"
#include "ha.h"
#include "ids.h"
#include "update.h"
#include "pkg.h"
#include "auth.h"
#include "console.h"
#include "feeds.h"
#include "response.h"
#include "logger.h"
#include "netutil.h"
#include "shellcmd.h"
#include "brand.h"

static firewall_ctx_t *g_fw = NULL;
static volatile sig_atomic_t g_stop   = 0;
static volatile sig_atomic_t g_reload = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* SIGHUP asks for a reload. The work happens in the main loop, not here --
 * a handler must not take locks or touch the network. */
static void on_hup(int sig) { (void)sig; g_reload = 1; }

static void banner(void) {
    printf("\n%s", BRAND_LOGO_ASCII);
    printf("        by %s - %s\n", BRAND_VENDOR, BRAND_TAGLINE);
    printf("        %s Edition  v%s (%s)\n\n",
           BRAND_EDITION, BRAND_VERSION, BRAND_BUILD);
}

static void usage(const char *argv0) {
    printf("%s - %s\n\n", BRAND_DAEMON, BRAND_FULL);
    printf("Usage: %s [options]\n\n", argv0);
    printf("  --enterprise-config FILE  segmentation / WAN / portal config\n");
    printf("                            (default " BRAND_CONFIG_DIR "/firex.conf)\n");
    printf("  --rules FILE              packet rule table (rules.conf)\n");
    printf("  --engine NAME             raw | nfqueue | xdp   (default nfqueue)\n");
    printf("  --iface NAME              interface for the packet engine\n");
    printf("  --blockpage-port N        portal port (default %d)\n", BLOCKPAGE_PORT);
    printf("  --no-blockpage            do not start the portal\n");
    printf("  --no-apply                load config but do not touch the network\n");
    printf("  --dump                    print the parsed configuration and exit\n");
    printf("  --check                   validate the configuration and exit\n");
    printf("  --save FILE               write the loaded config to FILE and exit\n");
    printf("  --users FILE              console user database\n");
    printf("  --genkey                  print a new WireGuard keypair and exit\n");
    printf("  --genpsk                  print a new WireGuard pre-shared key\n");
    printf("\n Platform:\n");
    printf("  --menu                    serial console menu\n");
    printf("  --slots                   show A/B slot status and exit\n");
    printf("  --write-grub FILE         write the A/B grub.cfg and exit\n");
    printf("  --verify FILE             check a signed update bundle and exit\n");
    printf("  --boot-attempt            charge one boot attempt (run at startup)\n");
    printf("  --confirm-boot            mark the running slot good and exit\n");
    printf("  --genupdkey               print a new update signing keypair\n");
    printf("  --passwd USER             set a console password (creates the user)\n");
    printf("  --role admin|viewer       role for a user --passwd creates\n");
    printf("  --allow-weak              let --passwd accept a short password\n");
    printf("  --no-splash               --write-grub: boot verbose, no splash\n");
    printf("  --gfxmode WxH             --write-grub: the boot video mode\n");
    printf("  --slots-file FILE         A/B state (default %s)\n",
           BRAND_STATE_DIR "/slots.conf");
    printf("  --keyring FILE            trusted update keys (default %s)\n",
           BRAND_CONFIG_DIR "/update-keys");
    printf("  --pkg-root DIR            where packages unpack (default /usr/local)\n");
    printf("  --pkg-db DIR              package records (default %s)\n",
           BRAND_STATE_DIR "/packages");
    printf("  --capture-dir DIR         where packet captures are written\n");
    printf("                            (default /run/firex, cleared on reboot)\n");
    printf("                            (default " BRAND_CONFIG_DIR "/users)\n");
    printf("  --log FILE                append decisions to FILE\n");
    printf("  --help\n\n");
    printf("Network provisioning and packet capture both require root.\n");
    printf("SIGHUP re-reads the config: it is validated first, and a failed\n");
    printf("apply restores what was running before.\n");
}


static const char *action_word(ivr_action_t a) {
    switch (a) {
        case IVR_ALLOW:     return "ALLOW";
        case IVR_LOG_ALLOW: return "LOG_ALLOW";
        case IVR_LOG_DENY:  return "LOG_DENY";
        default:            return "DENY";
    }
}

/* Print what was parsed, so an appliance config can be reviewed before it
 * reaches a live network. */
static void dump_config(void) {
    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];

    printf("\n=== WAN LINKS ===\n");
    for (int i = 0; i < g_netconf.wan_count; i++) {
        wan_config_t *w = &g_netconf.wan[i];
        printf("  wan%d  %-8s %-7s nat=%-3s bogons=%-3s ping=%-3s %s\n",
               i, w->ifname,
               w->mode == WAN_DHCP ? "dhcp" : w->mode == WAN_STATIC ? "static"
               : w->mode == WAN_PPPOE ? "pppoe" : "off",
               w->nat_enabled ? "yes" : "no",
               w->block_bogons ? "yes" : "no",
               w->respond_to_ping ? "yes" : "no",
               w->is_backup ? "(backup)" : "");
    }

    printf("\n=== PORTS ===\n");
    for (int i = 0; i < g_vlan.port_count; i++) {
        port_config_t *p = &g_vlan.ports[i];
        printf("  %-8s %-18s %-8s zone=%-6s pvid=%-4u vlans=",
               p->ifname, p->label, port_mode_name(p->mode),
               zone_name(p->zone), p->pvid);
        if (!p->allowed_count) printf("-");
        for (int j = 0; j < p->allowed_count; j++)
            printf("%s%u", j ? "," : "", p->allowed_vlans[j]);
        printf("\n");
    }

    printf("\n=== VLANS ===\n");
    for (int i = 0; i < g_vlan.vlan_count; i++) {
        vlan_config_t *v = &g_vlan.vlans[i];
        printf("  %-4u %-10s %-6s %s/%-2d gw=%-15s inet=%-3s ivr=%-3s iso=%-3s dhcp=%s\n",
               v->vlan_id, v->name, zone_name(v->zone),
               fx_ip_str(v->subnet, a, sizeof(a)), fx_netmask_to_cidr(v->netmask),
               fx_ip_str(v->gateway, b, sizeof(b)),
               v->internet_access ? "yes" : "NO",
               v->inter_vlan_routing ? "yes" : "NO",
               v->client_isolation ? "YES" : "no",
               v->dhcp_enabled ? "yes" : "no");
    }

    printf("\n=== ZONE MATRIX (row -> col) ===\n       ");
    for (int t = 0; t < ZONE_MAX; t++) printf("%-6.5s", zone_name(t));
    printf("\n");
    for (int f = 0; f < ZONE_MAX; f++) {
        printf("  %-5.4s", zone_name(f));
        for (int t = 0; t < ZONE_MAX; t++) {
            ivr_action_t x = g_vlan.zone_matrix[f][t];
            printf("%-6s", f == t ? "  -"
                   : x == IVR_ALLOW ? "  Y"
                   : x == IVR_LOG_ALLOW ? "  y*"
                   : x == IVR_LOG_DENY ? "  n*" : "  N");
        }
        printf("\n");
    }

    printf("\n=== INTER-VLAN ACL (priority order) ===\n");
    for (int i = 0; i < g_vlan.ivr_count; i++) {
        ivr_rule_t *r = &g_vlan.ivr[i];
        char pb[48];
        if (r->port_alias[0])        snprintf(pb, sizeof(pb), "$%s", r->port_alias);
        else if (!r->dst_port_start) snprintf(pb, sizeof(pb), "any");
        else if (r->dst_port_start == r->dst_port_end)
                                     snprintf(pb, sizeof(pb), "%u", r->dst_port_start);
        else snprintf(pb, sizeof(pb), "%u-%u", r->dst_port_start, r->dst_port_end);

        printf("  [%3d] %4u -> %-4u proto=%-4u port=%-14s %-9s  %s%s%s\n",
               r->priority, r->src_vlan, r->dst_vlan, r->protocol, pb,
               action_word(r->action), r->description,
               r->schedule[0] ? "  @" : "", r->schedule);
    }

    if (g_policy.alias_count) {
        printf("\n=== ALIASES ===\n");
        char buf[1024];
        for (int i = 0; i < g_policy.alias_count; i++) {
            alias_t *al = &g_policy.aliases[i];
            printf("  $%-18s %-8s %s\n", al->name,
                   policy_alias_kind_str(al->kind),
                   policy_entries_str(al, buf, sizeof(buf)));
        }
    }

    if (g_policy.schedule_count) {
        printf("\n=== SCHEDULES ===\n");
        char d[64], s1[8], s2[8];
        for (int i = 0; i < g_policy.schedule_count; i++) {
            schedule_t *sc = &g_policy.schedules[i];
            printf("  %-18s %-10s %s-%s  %s\n", sc->name,
                   policy_days_str(sc->days, d, sizeof(d)),
                   policy_hhmm_str(sc->start_min, s1, sizeof(s1)),
                   policy_hhmm_str(sc->end_min, s2, sizeof(s2)),
                   policy_window_active(sc, time(NULL)) ? "(active now)" : "");
        }
    }

    if (g_netconf.route_count) {
        printf("\n=== STATIC ROUTES ===\n");
        for (int i = 0; i < g_netconf.route_count; i++) {
            static_route_t *r = &g_netconf.routes[i];
            printf("  %s/%-3d via %-16s %-8s metric %-5d %s\n",
                   fx_ip_str(r->dest, a, sizeof(a)), fx_netmask_to_cidr(r->mask),
                   fx_ip_str(r->gateway, b, sizeof(b)),
                   r->ifname[0] ? r->ifname : "-", r->metric, r->description);
        }
    }

    if (g_vpn.wg_count) {
        printf("\n=== WIREGUARD ===\n");
        char fp[32];
        for (int i = 0; i < g_vpn.wg_count; i++) {
            wg_iface_t *w = &g_vpn.wg[i];
            printf("  %-6s port=%-6u %s/%-2d  zone=%-5s mtu=%-5d key=%s %s\n",
                   w->ifname, w->listen_port,
                   fx_ip_str(w->address, a, sizeof(a)),
                   fx_netmask_to_cidr(w->netmask), zone_name(w->zone), w->mtu,
                   wg_key_fingerprint(w->private_key, fp, sizeof(fp)),
                   w->enabled ? "" : "(disabled)");
            if (w->public_key[0])
                printf("         public key for peers: %s\n", w->public_key);
        }
        for (int i = 0; i < g_vpn.peer_count; i++) {
            wg_peer_t *p = &g_vpn.peers[i];
            printf("    peer %-20s on %-5s zone=%-5s %s\n", p->name, p->ifname,
                   zone_name(p->zone),
                   p->endpoint_host[0] ? "site-to-site" : "roaming");
            printf("         allowed: ");
            for (int k = 0; k < p->allowed_count; k++) {
                char nb[64];
                printf("%s%s", k ? ", " : "",
                       fx_cidr_str(p->allowed[k].ip, p->allowed[k].mask,
                                   nb, sizeof(nb)));
            }
            printf("\n");
        }
    }

    if (g_vpn.tunnel_count) {
        printf("\n=== IPSEC ===\n");
        char lb[64], rb[64];
        for (int i = 0; i < g_vpn.tunnel_count; i++) {
            ipsec_tunnel_t *t = &g_vpn.tunnels[i];
            printf("  %-14s %-18s %s <-> %s  %s zone=%s %s\n",
                   t->name, t->remote_host,
                   fx_cidr_str(t->local_subnet, t->local_mask, lb, sizeof(lb)),
                   fx_cidr_str(t->remote_subnet, t->remote_mask, rb, sizeof(rb)),
                   ike_version_str(t->version), zone_name(t->zone),
                   t->enabled ? "" : "(disabled)");
        }
    }

    printf("\n=== PUBLISHED SERVICES (DNAT) ===\n");
    for (int i = 0; i < g_netconf.forward_count; i++) {
        port_forward_t *f = &g_netconf.forwards[i];
        printf("  %-14s %s/%-6u -> %s:%u%s\n", f->name,
               f->protocol == 17 ? "udp" : "tcp", f->wan_port_start,
               fx_ip_str(f->internal_ip, a, sizeof(a)), f->internal_port,
               f->source_restrict ? "  (source restricted)" : "");
    }
    printf("\n");
}

int main(int argc, char **argv) {
    const char *ent_cfg   = BRAND_CONFIG_DIR "/firex.conf";
    const char *rules_cfg = NULL;
    const char *engine_s  = "nfqueue";
    const char *iface     = NULL;
    const char *logfile   = NULL;
    const char *users_cfg = BRAND_CONFIG_DIR "/users";
    const char *save_to   = NULL;
    const char *cap_dir   = "/run/firex";
    int  bp_port      = 0;
    bool want_bp      = true;
    bool apply_net    = true;
    bool do_dump      = false;
    bool do_check     = false;
    bool do_genkey    = false;
    bool do_genpsk    = false;

    const char *slots_file = BRAND_STATE_DIR "/slots.conf";
    const char *keyring_f  = BRAND_CONFIG_DIR "/update-keys";
    const char *pkg_root   = "/usr/local";
    const char *pkg_db     = BRAND_STATE_DIR "/packages";
    const char *verify_f   = NULL;
    const char *grub_out   = NULL;
    const char *passwd_user = NULL;
    const char *passwd_role = "admin";
    bool passwd_weak_ok = false;
    bool do_menu      = false;
    bool do_slots     = false;
    bool do_bootatt   = false;
    bool do_confirm   = false;
    bool do_updkey    = false;

    static struct option opts[] = {
        {"enterprise-config", required_argument, 0, 'c'},
        {"rules",             required_argument, 0, 'r'},
        {"engine",            required_argument, 0, 'e'},
        {"iface",             required_argument, 0, 'i'},
        {"blockpage-port",    required_argument, 0, 'p'},
        {"no-blockpage",      no_argument,       0, 'B'},
        {"no-apply",          no_argument,       0, 'N'},
        {"dump",              no_argument,       0, 'd'},
        {"check",             no_argument,       0, 'C'},
        {"save",              required_argument, 0, 'S'},
        {"users",             required_argument, 0, 'U'},
        {"capture-dir",       required_argument, 0, 'D'},
        {"genkey",            no_argument,       0, 'K'},
        {"genpsk",            no_argument,       0, 'P'},
        {"log",               required_argument, 0, 'l'},
        {"menu",              no_argument,       0, 'M'},
        {"slots",             no_argument,       0, 'L'},
        {"write-grub",        required_argument, 0, 1005},
        {"passwd",            required_argument, 0, 1006},
        {"allow-weak",        no_argument,       0, 1016},
        {"no-splash",         no_argument,       0, 1017},
        {"gfxmode",           required_argument, 0, 1018},
        {"role",              required_argument, 0, 1007},
        {"verify",            required_argument, 0, 'V'},
        {"boot-attempt",      no_argument,       0, 'A'},
        {"confirm-boot",      no_argument,       0, 'F'},
        {"genupdkey",         no_argument,       0, 'G'},
        {"slots-file",        required_argument, 0, 1001},
        {"keyring",           required_argument, 0, 1002},
        {"pkg-root",          required_argument, 0, 1003},
        {"pkg-db",            required_argument, 0, 1004},
        {"help",              no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "c:r:e:i:p:BNdCS:U:D:KPl:MLV:AFGh", opts, NULL)) != -1) {
        switch (c) {
            case 'c': ent_cfg = optarg; break;
            case 'r': rules_cfg = optarg; break;
            case 'e': engine_s = optarg; break;
            case 'i': iface = optarg; break;
            case 'p': bp_port = atoi(optarg); break;
            case 'B': want_bp = false; break;
            case 'N': apply_net = false; break;
            case 'd': do_dump = true; apply_net = false; want_bp = false; break;
            case 'C': do_check = true; apply_net = false; want_bp = false; break;
            case 'S': save_to = optarg; apply_net = false; want_bp = false; break;
            case 'U': users_cfg = optarg; break;
            case 'D': cap_dir = optarg; break;
            case 'K': do_genkey = true; break;
            case 'P': do_genpsk = true; break;
            case 'l': logfile = optarg; break;
            case 'M': do_menu = true; apply_net = false; want_bp = false; break;
            case 'L': do_slots = true; apply_net = false; want_bp = false; break;
            case 'V': verify_f = optarg; apply_net = false; want_bp = false; break;
            case 'A': do_bootatt = true; apply_net = false; want_bp = false; break;
            case 'F': do_confirm = true; apply_net = false; want_bp = false; break;
            case 'G': do_updkey = true; break;
            case 1001: slots_file = optarg; break;
            case 1002: keyring_f = optarg; break;
            case 1003: pkg_root  = optarg; break;
            case 1004: pkg_db    = optarg; break;
            case 1005: grub_out = optarg; apply_net = false; want_bp = false; break;
            case 1006: passwd_user = optarg; apply_net = false; want_bp = false; break;
            case 1007: passwd_role = optarg; break;
            case 1016: passwd_weak_ok = true; break;
            case 1017: slots_set_splash(false); break;
            case 1018: slots_set_gfxmode(optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (do_genkey || do_genpsk) {
        char priv[WG_KEY_B64_LEN], pub[WG_KEY_B64_LEN];
        if (wg_generate_keypair(priv, pub) != 0) {
            fprintf(stderr, "%s: key generation failed\n", BRAND_PRODUCT);
            return 1;
        }
        if (do_genpsk) {
            /* A pre-shared key is just 32 random bytes in the same encoding;
             * the private half of a throwaway pair is exactly that. */
            printf("%s\n", priv);
        } else {
            printf("private_key = %s\n", priv);
            printf("public_key  = %s\n", pub);
            fprintf(stderr, "\nGive the public key to the peer. Keep the "
                    "private key on this appliance only.\n");
        }
        explicit_bzero(priv, sizeof(priv));
        return 0;
    }

    if (do_updkey) {
        char priv[UPD_B64_LEN], pub[UPD_B64_LEN];
        if (upd_keygen(priv, pub) != 0) {
            fprintf(stderr, "%s: update key generation failed\n", BRAND_PRODUCT);
            return 1;
        }
        char id[UPD_KEYID_LEN] = "?";
        upd_keyid_from_b64(pub, id);
        printf("private: %s\n", priv);
        printf("keyring: %s %s build key\n", pub, BRAND_PRODUCT);
        printf("key id:  %s\n", id);
        fprintf(stderr, "\nPut the keyring line in %s on the appliance.\n"
                "Keep the private key on the build host; an appliance that "
                "can sign\nits own updates has no update signing.\n",
                BRAND_CONFIG_DIR "/update-keys");
        explicit_bzero(priv, sizeof(priv));
        return 0;
    }

    /* ---- A/B slots and bundle checks: no configuration needed ---- */

    if (passwd_user) {
        char pass[128];

        if (isatty(STDIN_FILENO)) {
            char again[128];
            struct termios old, quiet;
            bool restore = false;
            if (tcgetattr(STDIN_FILENO, &old) == 0) {
                quiet = old;
                quiet.c_lflag &= (tcflag_t)~ECHO;
                restore = (tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0);
            }
            printf("New password for %s: ", passwd_user);
            fflush(stdout);
            if (!fgets(pass, sizeof(pass), stdin)) { if (restore) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); return 1; }
            printf("\nRepeat: ");
            fflush(stdout);
            if (!fgets(again, sizeof(again), stdin)) { if (restore) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); return 1; }
            if (restore) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); printf("\n"); }

            pass[strcspn(pass, "\r\n")]   = '\0';
            again[strcspn(again, "\r\n")] = '\0';
            if (strcmp(pass, again) != 0) {
                fprintf(stderr, "%s: the passwords do not match\n", BRAND_PRODUCT);
                explicit_bzero(pass, sizeof(pass));
                explicit_bzero(again, sizeof(again));
                return 1;
            }
            explicit_bzero(again, sizeof(again));
        } else {
            /* Piped in, which is how the image build seeds the first account. */
            if (!fgets(pass, sizeof(pass), stdin)) {
                fprintf(stderr, "%s: no password on stdin\n", BRAND_PRODUCT);
                return 1;
            }
            pass[strcspn(pass, "\r\n")] = '\0';
        }

        /*
         * The image build seeds root/root and admin/admin, which are
         * shorter than anything an operator should be allowed to choose.
         * It passes --allow-weak to say so out loud rather than having
         * this limit quietly not apply to whoever pipes in a password.
         */
        if (!*pass) {
            fprintf(stderr, "%s: the password is empty\n", BRAND_PRODUCT);
            explicit_bzero(pass, sizeof(pass));
            return 1;
        }
        if (!passwd_weak_ok && strlen(pass) < AUTH_MIN_PASSWORD) {
            fprintf(stderr, "%s: the password must be at least %d characters\n",
                    BRAND_PRODUCT, AUTH_MIN_PASSWORD);
            explicit_bzero(pass, sizeof(pass));
            return 1;
        }

        auth_ctx_t a;
        memset(&a, 0, sizeof(a));
        /*
         * auth_init bootstraps an admin account when the database is
         * missing, printing a password nobody asked for. Load quietly
         * instead, and treat "no database yet" as an empty one.
         */
        if (auth_load_quiet(&a, users_cfg) != 0) {
            fprintf(stderr, "%s: cannot use %s\n", BRAND_PRODUCT, users_cfg);
            explicit_bzero(pass, sizeof(pass));
            return 1;
        }

        bool existed = false;
        for (int i = 0; i < a.user_count; i++)
            if (!strcmp(a.users[i].name, passwd_user)) existed = true;

        int rc = existed ? auth_set_password(&a, passwd_user, pass)
                         : auth_add_user(&a, passwd_user, pass,
                                         auth_role_from(passwd_role));
        explicit_bzero(pass, sizeof(pass));

        if (rc != 0) {
            fprintf(stderr, "%s: could not write %s\n", BRAND_PRODUCT, users_cfg);
            return 1;
        }
        printf("[%s] %s console user '%s' in %s\n", BRAND_PRODUCT,
               existed ? "updated" : "created", passwd_user, users_cfg);
        return 0;
    }

    if (grub_out) {
        slots_t sl;
        char err[256] = "";
        slots_load(&sl, slots_file, err, sizeof(err));

        char grub[8192];
        int n = slots_grub_config(&sl, grub, sizeof(grub));
        if (n <= 0) {
            fprintf(stderr, "[%s] could not render grub.cfg\n", BRAND_PRODUCT);
            return 1;
        }
        FILE *g = fopen(grub_out, "w");
        if (!g) { perror(grub_out); return 1; }
        fputs(grub, g);
        if (fclose(g) != 0) { perror(grub_out); return 1; }

        printf("[%s] wrote %s (%d bytes); next boot is slot %s\n",
               BRAND_PRODUCT, grub_out, n, slot_name(sl.next));
        return 0;
    }

    if (do_slots || do_bootatt || do_confirm) {
        slots_t sl;
        char err[256] = "";
        int rc = slots_load(&sl, slots_file, err, sizeof(err));
        if (rc < 0) {
            fprintf(stderr, "%s: %s\n", BRAND_PRODUCT, err);
            return 1;
        }
        if (rc == 1)
            fprintf(stderr, "[%s] %s\n", BRAND_PRODUCT, err);

        if (do_bootatt) {
            bool reboot_needed = slots_boot_attempt(&sl);
            if (slots_save(&sl, slots_file, err, sizeof(err)) != 0) {
                fprintf(stderr, "%s: %s\n", BRAND_PRODUCT, err);
                return 1;
            }
            if (reboot_needed) {
                printf("[%s] slot %s used up its boot attempts and is marked "
                       "bad.\n[%s] the next boot returns to slot %s.\n",
                       BRAND_PRODUCT, slot_name(sl.running),
                       BRAND_PRODUCT, slot_name(sl.next));
                return 3;      /* the unit file turns this into a reboot */
            }
            const slot_t *run = &sl.slot[sl.running];
            if (run->state == SLOT_PENDING)
                printf("[%s] slot %s is unconfirmed; %d attempt(s) left.\n",
                       BRAND_PRODUCT, slot_name(sl.running), run->tries_left);
            return 0;
        }

        if (do_confirm) {
            slots_confirm(&sl);
            if (slots_save(&sl, slots_file, err, sizeof(err)) != 0) {
                fprintf(stderr, "%s: %s\n", BRAND_PRODUCT, err);
                return 1;
            }
            printf("[%s] slot %s confirmed good.\n",
                   BRAND_PRODUCT, slot_name(sl.running));
            return 0;
        }

        printf("\n  %-6s %-9s %-10s %-7s %-16s\n",
               "SLOT", "VERSION", "STATE", "TRIES", "LABEL");
        for (int i = 0; i < 2; i++) {
            const slot_t *x = &sl.slot[i];
            printf("  %-6s %-9s %-10s %-7d %-16s%s\n",
                   slot_name((slot_id_t)i), x->version[0] ? x->version : "-",
                   slot_state_name(x->state), x->tries_left, x->label,
                   (slot_id_t)i == sl.running ? "  <- running" : "");
        }
        printf("\n  next boot: slot %s\n\n", slot_name(sl.next));

        char grub[4096];
        if (slots_grub_config(&sl, grub, sizeof(grub)) > 0)
            printf("--- the grub.cfg this state produces ---\n%s\n", grub);
        return 0;
    }

    if (verify_f) {
        upd_keyring_t ring;
        char err[512] = "";
        if (upd_keyring_load(&ring, keyring_f, err, sizeof(err)) != 0) {
            fprintf(stderr, "[%s] no usable keyring: %s\n", BRAND_PRODUCT, err);
            return 1;
        }
        upd_meta_t m;
        if (upd_bundle_verify(verify_f, &ring, BRAND_VERSION, &m,
                              err, sizeof(err)) != 0) {
            fprintf(stderr, "\n[%s] REJECTED: %s\n\n", BRAND_PRODUCT, err);
            return 2;
        }
        printf("\n  %-12s %s\n", "bundle:", verify_f);
        printf("  %-12s %s\n", "kind:",
               m.kind == UPD_KIND_PACKAGE ? "package" : "system image");
        printf("  %-12s %s\n", "name:", m.name);
        printf("  %-12s %s\n", "version:", m.version);
        printf("  %-12s %s\n", "built:", m.build);
        printf("  %-12s %llu bytes\n", "size:", (unsigned long long)m.size);
        printf("  %-12s %s\n", "signer:", m.signer);
        if (m.description[0]) printf("  %-12s %s\n", "about:", m.description);
        printf("\n[%s] signature and payload digest are valid "
               "(%d trusted key(s)).\n\n", BRAND_PRODUCT, ring.count);
        return 0;
    }

    banner();

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP,  on_hup);
    signal(SIGPIPE, SIG_IGN);

    g_fw = fw_create();
    if (!g_fw) { fprintf(stderr, "out of memory\n"); return 1; }

    /* ═══ Packet rules ═══ */
    if (rules_cfg && fw_load_config(g_fw, rules_cfg) != 0)
        fprintf(stderr, "[%s] could not load rules from %s\n", BRAND_PRODUCT, rules_cfg);

    /* ═══ Enterprise segmentation ═══ */
    printf("[SEG] Initialising segmentation subsystem...\n");
    vlan_init(&g_vlan);
    netconf_init(&g_netconf);
    policy_init(&g_policy);
    vpn_init(&g_vpn);
    vlan_set_policy(&g_vlan, &g_policy);

    memset(&g_blockpage, 0, sizeof(g_blockpage));
    g_blockpage.port = bp_port ? bp_port : BLOCKPAGE_PORT;
    snprintf(g_blockpage.org_name, sizeof(g_blockpage.org_name), "%s", BRAND_VENDOR);
    snprintf(g_blockpage.admin_contact, sizeof(g_blockpage.admin_contact),
             "%s", BRAND_SUPPORT_EMAIL);
    g_blockpage.show_logo      = true;
    g_blockpage.show_technical = true;
    g_blockpage.allow_override = true;

    if (firex_load_enterprise_config_ex(ent_cfg, &g_vlan, &g_netconf,
                                        &g_blockpage, &g_policy, &g_vpn) != 0)
        fprintf(stderr, "[%s] continuing without enterprise config\n", BRAND_PRODUCT);

    if (bp_port) g_blockpage.port = bp_port;   /* command line wins */

    if (do_dump) {
        dump_config();
        vlan_shutdown(&g_vlan);
        netconf_shutdown(&g_netconf);
        fw_destroy(g_fw);
        return 0;
    }

    /* --menu: the serial console. The configuration is loaded by this
     * point, so the menu can show real interface and VLAN state. */
    if (do_menu) {
        slots_t sl;
        pkg_ctx_t pk;
        char err[256] = "";
        char host[64] = "firex";

        slots_load(&sl, slots_file, err, sizeof(err));
        pkg_init(&pk, pkg_root, pkg_db);
        pkg_db_load(&pk, NULL, 0);
        gethostname(host, sizeof(host) - 1);

        console_ctx_t cc = {
            .vlan = &g_vlan, .netconf = &g_netconf, .pkg = &pk, .slots = &sl,
            .slots_path = slots_file, .keyring_path = keyring_f,
            .config_path = ent_cfg, .users_path = users_cfg, .hostname = host,
        };
        int rc = console_run(&cc);

        vlan_shutdown(&g_vlan);
        netconf_shutdown(&g_netconf);
        fw_destroy(g_fw);
        return rc;
    }

    /* --check: the config is already parsed, so validate what we have and
     * report. Nothing is touched and nothing is started. */
    if (do_check) {
        cfg_validate_t res;
        int bad = firex_validate(&g_vlan, &g_netconf, &g_blockpage, &g_vpn, &res);

        printf("  %-11s %d\n  %-11s %d\n  %-11s %d\n  %-11s %d\n"
               "  %-11s %d\n  %-11s %d\n  %-11s %d\n  %-11s %d\n",
               "vlans:", res.vlans, "ports:", res.ports, "acls:", res.acls,
               "wan:", res.wans, "forwards:", res.forwards,
               "aliases:", res.aliases, "schedules:", res.schedules,
               "routes:", res.routes);
        if (g_netconf.shaping.enabled)
            printf("  %-11s %s, up %d / down %d Mbit%s\n", "shaping:",
                   qdisc_name(g_netconf.shaping.qdisc),
                   g_netconf.shaping.wan_up_mbps,
                   g_netconf.shaping.wan_down_mbps,
                   g_netconf.shaping.ingress_shaping ? ", ingress via IFB" : "");
        if (g_netconf.portal.enabled)
            printf("  %-11s %s auth, %d min session\n", "portal:",
                   portal_auth_name(g_netconf.portal.auth),
                   g_netconf.portal.session_minutes
                     ? g_netconf.portal.session_minutes : 240);
        if (g_netconf.threat.enabled)
            printf("  %-11s %s, %d feed(s)%s\n", "threat:",
                   g_netconf.threat.inline_mode ? "inline" : "alert-only",
                   g_netconf.feed_count,
                   g_netconf.threat.rules_path[0] ? ", rules loaded" : "");
        if (g_netconf.response.enabled)
            printf("  %-11s %s at score %d, %d min\n", "response:",
                   g_netconf.response.quarantine ? "quarantine" : "block",
                   g_netconf.response.threshold,
                   g_netconf.response.block_minutes);
        if (g_netconf.ha.enabled)
            printf("  %-11s %s, VRID %d, priority %d, peer %s\n", "ha:",
                   ha_role_name(g_netconf.ha.role),
                   g_netconf.ha.vrrp_id ? g_netconf.ha.vrrp_id : HA_DEFAULT_VRID,
                   g_netconf.ha.priority,
                   g_netconf.ha.peer_address[0]
                     ? g_netconf.ha.peer_address : "(none)");
        if (g_netconf.telemetry.syslog_host[0])
            printf("  %-11s %s:%u/%s\n", "syslog:",
                   g_netconf.telemetry.syslog_host,
                   g_netconf.telemetry.syslog_port
                     ? g_netconf.telemetry.syslog_port : 514,
                   g_netconf.telemetry.syslog_tcp ? "tcp" : "udp");
        if (g_netconf.telemetry.netflow_host[0])
            printf("  %-11s %s:%u\n", "netflow:",
                   g_netconf.telemetry.netflow_host,
                   g_netconf.telemetry.netflow_port
                     ? g_netconf.telemetry.netflow_port : 2055);
        if (res.wg_ifaces || res.ipsec_tunnels)
            printf("  %-11s %d\n  %-11s %d\n  %-11s %d\n",
                   "wg links:", res.wg_ifaces, "wg peers:", res.wg_peers,
                   "ipsec:", res.ipsec_tunnels);

        /* Platform state is not part of config validity, but an operator
         * running --check wants to know which root they are on and what
         * the next boot will pick. */
        {
            slots_t sl;
            pkg_ctx_t pk;
            slots_load(&sl, slots_file, NULL, 0);
            printf("  %-11s %s (%s), next boot %s\n", "slot:",
                   slot_name(sl.running),
                   slot_state_name(sl.slot[sl.running].state),
                   slot_name(sl.next));

            pkg_init(&pk, pkg_root, pkg_db);
            pkg_db_load(&pk, NULL, 0);
            if (pk.count) printf("  %-11s %d installed\n", "packages:", pk.count);

            upd_keyring_t ring;
            if (upd_keyring_load(&ring, keyring_f, NULL, 0) == 0)
                printf("  %-11s %d trusted key(s)\n", "update:", ring.count);
            else
                printf("  %-11s no keyring at %s -- updates cannot be "
                       "verified\n", "update:", keyring_f);
        }

        if (bad != 0)
            printf("\n[%s] INVALID: %s\n\n", BRAND_PRODUCT, res.error);
        else if (res.warnings)
            printf("\n[%s] valid, with %d warning(s). First: %s\n\n",
                   BRAND_PRODUCT, res.warnings, res.warning);
        else
            printf("\n[%s] configuration is valid.\n\n", BRAND_PRODUCT);

        vlan_shutdown(&g_vlan);
        netconf_shutdown(&g_netconf);
        fw_destroy(g_fw);
        return bad == 0 ? 0 : 2;
    }

    /* --save: round-trip the loaded config out to a file. This is how a
     * hand-written config gets normalised, and what the round-trip test
     * drives. */
    if (save_to) {
        cfg_meta_t meta;
        memset(&meta, 0, sizeof(meta));
        meta.revision = 1;
        meta.when     = time(NULL);
        snprintf(meta.author, sizeof(meta.author), "firexd --save");
        snprintf(meta.note, sizeof(meta.note), "normalised from %s", ent_cfg);

        int rc = firex_save_enterprise_config_ex(save_to, &g_vlan, &g_netconf,
                                                 &g_blockpage, &g_policy,
                                                 &g_vpn, &meta);
        if (rc == 0) printf("[%s] configuration written to %s\n",
                            BRAND_PRODUCT, save_to);
        else fprintf(stderr, "[%s] could not write %s\n", BRAND_PRODUCT, save_to);

        vlan_shutdown(&g_vlan);
        netconf_shutdown(&g_netconf);
        fw_destroy(g_fw);
        return rc == 0 ? 0 : 1;
    }

    if (apply_net && geteuid() != 0) {
        fprintf(stderr, "\n[%s] NOT RUNNING AS ROOT - network provisioning and "
                "packet capture both need it.\n"
                "       Re-run with sudo, or pass --no-apply to check the "
                "configuration only.\n\n", BRAND_PRODUCT);
        fw_destroy(g_fw);
        return 1;
    }

    /* ═══ Network provisioning ═══ */
    /* ═══ Air gap ═══
     *
     * FIRST, and the order is load-bearing. airgap_bind_egress() is what
     * makes every other subsystem's outbound traffic pass the gap, so it
     * has to be in place before any of them can open a socket. The feed
     * refresher used to start sixty lines above this block and got its
     * first fetch away while the appliance was still, on paper, isolated.
     */
    airgap_init(&g_airgap);
    {
        ag_cfg_t *ac = &g_netconf.airgap;
        g_airgap.require_time_sync = ac->require_time_sync;
        g_airgap.log_denied        = ac->log_denied;
        for (int i = 0; i < g_netconf.airgap_window_count; i++) {
            ag_window_t *w = &g_netconf.airgap_windows[i];
            if (w->used)
                airgap_add_window(&g_airgap, w->name, w->days, w->start_min,
                                  w->end_min, w->allow_in, w->allow_out);
        }
        airgap_set_mode(&g_airgap, ac->mode, "configuration");
        if (ac->mode != AG_CONNECTED)
            printf("[%s] Air gap: %s -- %s\n", BRAND_PRODUCT,
                   airgap_mode_label(ac->mode), g_airgap.state_reason);
    }

    airgap_bind_egress(&g_airgap);

    /*
     * The administrative trail, opened before anything can be
     * administered. Not fatal when the directory is unwritable -- the ring
     * still answers /api/audit, and an appliance that refuses to boot
     * because it cannot log is one an attacker takes offline by filling a
     * disk.
     */
    audit_open(&g_audit, BRAND_LOG_DIR "/audit.log");
    audit_record(&g_audit, "system", 0, AUDIT_OK, "daemon.start",
                 BRAND_PRODUCT " " BRAND_VERSION,
                 "air gap %s, console TLS pending",
                 airgap_mode_name(g_netconf.airgap.mode));
    {
        char why[256];
        if (audit_verify(g_audit.path, why, sizeof(why)) != 0)
            fprintf(stderr, "[%s] AUDIT TRAIL: %s\n", BRAND_PRODUCT, why);
        else
            printf("[%s] Audit trail: %s\n", BRAND_PRODUCT, why);
    }

    /* ═══ Threat layer ═══ */
    ids_init(&g_ids);
    feeds_init(&g_feeds);
    response_init(&g_response, &g_netconf.response, apply_net);

    if (g_netconf.threat.enabled) {
        g_ids.enabled     = true;
        g_ids.inline_mode = g_netconf.threat.inline_mode;

        if (g_netconf.threat.rules_path[0]) {
            int bad = 0;
            int loaded = ids_load_file(&g_ids, g_netconf.threat.rules_path, &bad);
            if (loaded < 0)
                fprintf(stderr, "[%s] cannot read the rules file %s\n",
                        BRAND_PRODUCT, g_netconf.threat.rules_path);
            else
                printf("[%s] IDS: %d signature(s) loaded%s%s\n", BRAND_PRODUCT,
                       loaded, bad ? ", " : "",
                       bad ? "some rejected" : "");
        }
        ids_compile(&g_ids);

        if (!g_ids.inline_mode)
            printf("[%s] IDS: alert-only; drop rules will report, not drop\n",
                   BRAND_PRODUCT);

        g_feeds.enabled = g_netconf.threat.feeds_enabled;
        for (int i = 0; i < g_netconf.feed_count; i++)
            feeds_add(&g_feeds, &g_netconf.feeds[i]);
        feeds_start(&g_feeds);
    }

    response_start(&g_response);

    /* ═══ Live malware protection ═══ */
    mw_init(&g_malware);
    mw_load_builtin_patterns(&g_malware);
    {
        mw_cfg_t *mc = &g_netconf.malware;
        g_malware.enabled = mc->enabled;
        g_malware.block   = mc->block;
        g_malware.scan_uploads = mc->scan_uploads;
        if (mc->max_object_kb > 0) {
            size_t want = (size_t)mc->max_object_kb * 1024;
            g_malware.max_object = want < MW_FLOW_BUF ? want : MW_FLOW_BUF;
        }
        if (mc->flow_idle_seconds > 0)
            g_malware.flow_idle_seconds = mc->flow_idle_seconds;

        if (mc->enabled && mc->db_path[0]) {
            int n = mw_load_hashes(&g_malware, mc->db_path);
            if (n < 0)
                fprintf(stderr, "[%s] malware: cannot read %s; "
                                "running on built-in patterns only\n",
                        BRAND_PRODUCT, mc->db_path);
            else
                printf("[%s] Malware: %d hash(es) loaded from %s\n",
                       BRAND_PRODUCT, n, mc->db_path);
        }
        if (mc->enabled)
            printf("[%s] Malware: %s, %d pattern(s), objects up to %zu KB\n",
                   BRAND_PRODUCT, mc->block ? "blocking" : "detect-only",
                   g_malware.pattern_count, g_malware.max_object / 1024);
    }

    ha_init(&g_ha, &g_netconf.ha);
    if (g_netconf.ha.enabled) {
        /* Under VRRP the gateways are virtual; the VLAN layer must not
         * assign them or both nodes would answer for the same address. */
        g_vlan.ha_owns_gateways = true;
    }

    if (apply_net) {
        printf("[SEG] Bringing up WAN links...\n");
        netconf_apply_wan(&g_netconf);

        printf("[SEG] Provisioning VLAN segments...\n");
        vlan_apply_to_system(&g_vlan);

        printf("[SEG] Applying NAT policy...\n");
        netconf_apply_nat(&g_netconf, &g_vlan);

        printf("[SEG] Publishing port forwards...\n");
        netconf_apply_forwards(&g_netconf);

        if (g_netconf.route_count) {
            printf("[SEG] Installing static routes...\n");
            netconf_apply_routes(&g_netconf);
        }

        if (g_vpn.wg_count)     vpn_apply_wg(&g_vpn);
        if (g_vpn.tunnel_count) vpn_apply_ipsec(&g_vpn);

        if (g_netconf.shaping.enabled) {
            printf("[SEG] Applying traffic shaping...\n");
            shaper_init(&g_shaper, &g_netconf.shaping);
            shaper_apply(&g_shaper, &g_vlan, &g_netconf);
        }

        if (g_netconf.threat.enabled)
            printf("  %-11s %s, %d feed(s)%s\n", "threat:",
                   g_netconf.threat.inline_mode ? "inline" : "alert-only",
                   g_netconf.feed_count,
                   g_netconf.threat.rules_path[0] ? ", rules loaded" : "");
        if (g_netconf.response.enabled)
            printf("  %-11s %s at score %d, %d min\n", "response:",
                   g_netconf.response.quarantine ? "quarantine" : "block",
                   g_netconf.response.threshold,
                   g_netconf.response.block_minutes);
        if (g_netconf.ha.enabled) {
            printf("[SEG] Configuring high availability...\n");
            ha_apply(&g_ha, &g_vlan);
        }

        if (g_netconf.response.enabled) {
            printf("[SEG] Arming automatic response...\n");
            response_install_rules(&g_response);
        }

        printf("[SEG] Generating DHCP scopes...\n");
        if (netconf_generate_dhcp(&g_netconf, &g_vlan, "/etc/dnsmasq.conf") == 0) {
            fx_try("killall dnsmasq 2>/dev/null");
            fx_try("dnsmasq -C /etc/dnsmasq.conf 2>/dev/null &");
        }
    } else {
        printf("[SEG] --no-apply: configuration parsed, network left untouched.\n");
    }

    /* ═══ Block page portal ═══ */
    if (want_bp && g_blockpage.enabled) {
        portal_init(&g_portal, &g_netconf.portal, apply_net);
        portal_start(&g_portal);

        webui_init(users_cfg, ent_cfg);
        webui_set_runtime(ent_cfg, apply_net);

        /* Make sure there is always a revision 1 to roll back to, so the
         * shipped configuration is itself a recoverable point. */
        if (cfgstore_latest(&g_cfgstore) == 0)
            cfgstore_commit(&g_cfgstore, &g_vlan, &g_netconf, &g_blockpage,
                            &g_policy, &g_vpn,
                            "system", "initial configuration at first start");

        webui_attach(&g_blockpage);

        /*
         * The console's own listener. Default 8443, and bound to the
         * management zone's gateway when there is one -- an appliance
         * whose console answers on the guest VLAN is an appliance whose
         * login page a quarantined host can reach.
         */
        {
            int cport = g_netconf.console_port ? g_netconf.console_port
                                               : CONSOLE_PORT;
            uint32_t cbind = INADDR_ANY;
            const char *how = "every interface";

            const char *want = g_netconf.console_bind;
            if (!want[0] || !strcasecmp(want, "mgmt")) {
                for (int i = 0; i < g_vlan.vlan_count; i++) {
                    vlan_config_t *v = &g_vlan.vlans[i];
                    if (v->enabled && v->zone == ZONE_MGMT && v->gateway) {
                        cbind = v->gateway;
                        how = "the management zone";
                        break;
                    }
                }
            } else if (!strcasecmp(want, "any")) {
                /* Explicitly asked for; no warning below. */
                how = "every interface (configured)";
            } else {
                struct in_addr in;
                if (inet_pton(AF_INET, want, &in) == 1) {
                    cbind = in.s_addr;
                    how = "the configured address";
                } else {
                    fprintf(stderr, "[%s] console bind '%s' is not an address, "
                                    "not \"mgmt\" and not \"any\"; "
                                    "falling back to the management zone\n",
                            BRAND_PRODUCT, want);
                }
            }

            if (blockpage_set_admin(&g_blockpage, cport, cbind) != 0) {
                fprintf(stderr, "[%s] refusing to start: the console and the "
                                "block page would share one listener\n",
                        BRAND_PRODUCT);
                fw_destroy(g_fw);
                return 1;
            }
            printf("[%s] Console listener: port %d on %s\n",
                   BRAND_PRODUCT, cport, how);

            /*
             * TLS, unless the config explicitly says otherwise. The default
             * is on: an appliance whose management console ships in the
             * clear is one whose first deployment is already a finding, and
             * a default of "off unless configured" is a default that
             * survives exactly as long as nobody reads the file.
             */
            bool want_tls = g_netconf.console_tls_set
                            ? g_netconf.console_tls : true;
            if (want_tls) {
                const char *crt = g_netconf.console_tls_cert[0]
                    ? g_netconf.console_tls_cert
                    : BRAND_CONFIG_DIR "/console.crt";
                const char *key = g_netconf.console_tls_key[0]
                    ? g_netconf.console_tls_key
                    : BRAND_CONFIG_DIR "/console.key";

                if (blockpage_set_tls(&g_blockpage, crt, key) == 0) {
                    printf("[%s]   TLS enabled; certificate fingerprint\n"
                           "[%s]   SHA-256 %s\n",
                           BRAND_PRODUCT, BRAND_PRODUCT,
                           g_blockpage.tls_fingerprint);
                    printf("[%s]   compare that on the browser's first-visit "
                           "warning before accepting it\n", BRAND_PRODUCT);
                } else {
                    fprintf(stderr, "[%s]   WARNING: the console is serving "
                            "WITHOUT TLS; credentials will cross the "
                            "management network in the clear\n", BRAND_PRODUCT);
                }
            } else {
                fprintf(stderr, "[%s]   TLS is switched off in the "
                        "configuration; the console is serving in the clear\n",
                        BRAND_PRODUCT);
            }
            if (cbind == INADDR_ANY && (!want[0] || !strcasecmp(want, "mgmt")))
                printf("[%s]   no management-zone VLAN found, so it answers "
                       "everywhere; set [console] bind to narrow it\n",
                       BRAND_PRODUCT);
        }

        if (blockpage_start(&g_blockpage) == 0 && apply_net) {
            /* The portal owns the interception now: it matches on a client
             * NOT being authenticated, rather than on a quarantine set that
             * nothing ever filled. */
            for (int i = 0; i < g_vlan.vlan_count; i++) {
                if (g_vlan.vlans[i].captive_portal && g_vlan.vlans[i].gateway) {
                    char pip[INET_ADDRSTRLEN];
                    fx_ip_str(g_vlan.vlans[i].gateway, pip, sizeof(pip));
                    portal_install_rules(&g_portal, &g_vlan, pip,
                                         g_blockpage.port);
                    break;
                }
            }
        }
    }

    /* ═══ Gateway monitoring / multi-WAN failover ═══ */
    gwmon_init(&g_gwmon, &g_netconf, apply_net);
    gwmon_start(&g_gwmon);

    /* ═══ Observability ═══ */
    capture_init(&g_capture);
    webui_set_capture_dir(cap_dir);

    hist_init(&g_hist, g_fw, g_netconf.telemetry.history_interval);
    hist_start(&g_hist);

    telemetry_init(&g_telemetry, &g_netconf.telemetry);
    telemetry_start(&g_telemetry);
    telemetry_log(&g_telemetry, SYSLOG_NOTICE, "START",
                  "%s %s started: %d VLANs, %d ACLs, %d WAN link(s)",
                  BRAND_PRODUCT, BRAND_VERSION, g_vlan.vlan_count,
                  g_vlan.ivr_count, g_netconf.wan_count);

    /* ═══ Logging ═══ */
    if (logfile) logger_init(g_fw, logfile);

    /* ═══ Packet engine ═══ */
    firex_inspect_enable(g_fw);

    engine_t eng = ENGINE_NFQUEUE;
    if      (!strcasecmp(engine_s, "raw")) eng = ENGINE_RAW_SOCKET;
    else if (!strcasecmp(engine_s, "xdp")) eng = ENGINE_XDP;

    if (!iface) {
        /* Fall back to the first WAN link, then the first configured port. */
        if (g_netconf.wan_count > 0 && g_netconf.wan[0].ifname[0])
            iface = g_netconf.wan[0].ifname;
        else if (g_vlan.port_count > 0)
            iface = g_vlan.ports[0].ifname;
    }

    if (apply_net && iface) {
        printf("[%s] Starting %s engine on %s...\n",
               BRAND_PRODUCT, engine_name(eng), iface);
        if (engine_start(g_fw, iface, eng) != 0) {
            const char *detail = engine_detail(eng);
            fprintf(stderr, "[%s] engine failed to start%s%s\n", BRAND_PRODUCT,
                    detail ? ": " : "", detail ? detail : "");
        }
    } else if (!iface) {
        fprintf(stderr, "[%s] no interface to bind to; pass --iface\n", BRAND_PRODUCT);
    }

    printf("\n  ==================================================\n");
    printf("    %s is ACTIVE - %s\n", BRAND_PRODUCT, BRAND_TAGLINE);
    printf("    Block Portal  : http://<gateway>:%d\n", g_blockpage.port);
    /*
     * The scheme is read from the listener, not written out. A banner that
     * says http:// over a TLS listener sends the operator to a URL that
     * cannot connect; one that says https:// over a cleartext listener is
     * worse, because it connects to nothing and they conclude the console
     * is down rather than that it is unencrypted.
     */
    printf("    Admin Console : %s://<mgmt>:%d/ui\n",
           blockpage_tls_active(&g_blockpage) ? "https" : "http",
           g_blockpage.admin_port);
    if (!blockpage_tls_active(&g_blockpage))
        printf("                    (NOT ENCRYPTED)\n");
    printf("    Support       : %s\n", BRAND_SUPPORT_EMAIL);
    printf("  ==================================================\n\n");

    /* ═══ Run ═══ */
    while (!g_stop) {
        struct timespec ts = { 5, 0 };
        nanosleep(&ts, NULL);
        if (g_stop) break;

        if (g_reload) {
            g_reload = 0;
            printf("[%s] SIGHUP: reloading %s\n", BRAND_PRODUCT, ent_cfg);

            char err[CFG_ERR_LEN];
            if (firex_reload_file(ent_cfg, apply_net, err, sizeof(err)) != 0)
                fprintf(stderr, "[%s] reload rejected: %s\n", BRAND_PRODUCT, err);
            else
                printf("[%s] reload complete.\n", BRAND_PRODUCT);
            fflush(stdout);
        }

        /* Housekeeping. The air gap is re-evaluated every tick because a
         * scheduled window opens and shuts on the clock with nothing else
         * to drive it, and idle reassembly buffers are released so a flow
         * that stopped mid-download does not hold a slot for ever. */
        {
            time_t now = time(NULL);
            if (airgap_tick(&g_airgap, now))
                printf("[%s] Air gap: %s\n", BRAND_PRODUCT, g_airgap.state_reason);
            mw_gc(&g_malware, now);
        }

        fw_stats_t st = fw_get_stats(g_fw);

        char wanbuf[96] = "";
        gw_state_t gs[2];
        int gactive = -1;
        int gn = gwmon_snapshot(&g_gwmon, gs, 2, &gactive);
        for (int i = 0, o = 0; i < gn && o < (int)sizeof(wanbuf) - 24; i++)
            o += snprintf(wanbuf + o, sizeof(wanbuf) - (size_t)o,
                          " wan%d:%s%s", i, gwmon_status_str(gs[i].status),
                          i == gactive ? "*" : "");

        char thbuf[48] = "";
        if (g_ids.enabled)
            snprintf(thbuf, sizeof(thbuf), " | IDS:%lu/%lu",
                     g_ids.matched, g_ids.scanned);

        char habuf[32] = "";
        if (g_netconf.threat.enabled)
            printf("  %-11s %s, %d feed(s)%s\n", "threat:",
                   g_netconf.threat.inline_mode ? "inline" : "alert-only",
                   g_netconf.feed_count,
                   g_netconf.threat.rules_path[0] ? ", rules loaded" : "");
        if (g_netconf.response.enabled)
            printf("  %-11s %s at score %d, %d min\n", "response:",
                   g_netconf.response.quarantine ? "quarantine" : "block",
                   g_netconf.response.threshold,
                   g_netconf.response.block_minutes);
        if (g_netconf.ha.enabled)
            snprintf(habuf, sizeof(habuf), " | HA:%s",
                     ha_state_name(ha_read_state(&g_ha)));

        printf("[%s] pkts:%lu allow:%lu block:%lu | VLANs:%d "
               "IVR-allow:%lu IVR-deny:%lu tag-viol:%lu | pages:%lu |%s%s%s\n",
               BRAND_PRODUCT, st.total_packets, st.allowed, st.blocked,
               g_vlan.vlan_count, g_vlan.inter_vlan_allowed,
               g_vlan.inter_vlan_denied, g_vlan.vlan_violations,
               g_blockpage.pages_served, wanbuf[0] ? wanbuf : " wan:-",
               habuf, thbuf);
        fflush(stdout);
    }

    /* ═══ Shutdown ═══ */
    printf("\n[%s] Shutting down...\n", BRAND_PRODUCT);
    telemetry_log(&g_telemetry, SYSLOG_NOTICE, "STOP", "%s shutting down",
                  BRAND_PRODUCT);
    engine_stop(g_fw);
    hist_shutdown(&g_hist);
    capture_shutdown(&g_capture);
    telemetry_shutdown(&g_telemetry);
    gwmon_shutdown(&g_gwmon);
    blockpage_stop(&g_blockpage);
    webui_shutdown();
    if (apply_net) {
        response_teardown_rules(&g_response);
        ha_teardown(&g_ha);
        portal_teardown_rules(&g_portal);
        shaper_teardown(&g_shaper, &g_vlan, &g_netconf);
        vpn_teardown_ipsec(&g_vpn);
        vpn_teardown_wg(&g_vpn);
        vlan_teardown_system(&g_vlan);
    }
    logger_close(g_fw);
    vlan_shutdown(&g_vlan);
    netconf_shutdown(&g_netconf);
    policy_shutdown(&g_policy);
    portal_shutdown(&g_portal);
    ha_shutdown(&g_ha);
    ids_shutdown(&g_ids);
    feeds_shutdown(&g_feeds);
    mw_shutdown(&g_malware);
    audit_record(&g_audit, "system", 0, AUDIT_OK, "daemon.stop",
                 BRAND_PRODUCT, "shutting down");
    audit_close(&g_audit);
    airgap_shutdown(&g_airgap);
    response_shutdown(&g_response);
    shaper_shutdown(&g_shaper);
    vpn_shutdown(&g_vpn);
    fw_destroy(g_fw);

    if (fx_run_failures())
        fprintf(stderr, "[%s] %u provisioning command(s) reported failure\n",
                BRAND_PRODUCT, fx_run_failures());

    printf("[%s] Stopped.\n", BRAND_PRODUCT);
    return 0;
}
