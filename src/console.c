/*
 * Serial console menu.
 *
 * Deliberately plain: no colour, no cursor addressing, nothing that
 * depends on the terminal being anything better than a 80x24 VT100 over
 * 115200 baud. An operator reaches this when the appliance is in trouble,
 * and a menu that needs a working terminfo database is a menu that is not
 * there when it matters.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include <termios.h>
#include <arpa/inet.h>

#include "console.h"
#include "auth.h"
#include "shellcmd.h"
#include "brand.h"

/* ── the menu table ─────────────────────────────────────────── */

static const console_item_t ITEMS[] = {
    { 0,  CON_LOGOUT,   "Logout (or press Ctrl-D)",          false, false },
    { 1,  CON_STATUS,   "Show firewall status",              false, false },
    { 2,  CON_IFACES,   "Show interface assignments",        false, false },
    { 3,  CON_SETIP,    "Set an interface IP address",       false, true  },
    { 4,  CON_PASSWD,   "Reset the console password",        false, true  },
    { 5,  CON_PING,     "Ping a host",                       false, false },
    { 6,  CON_RELOAD,   "Reload the configuration",          false, true  },
    { 7,  CON_UPDATE,   "Install a signed update bundle",    true,  true  },
    { 8,  CON_SLOTS,    "Show A/B slot status",              false, false },
    { 9,  CON_ROLLBACK, "Roll back to the other slot",       true,  true  },
    { 10, CON_PACKAGES, "Packages",                          false, true  },
    { 11, CON_FACTORY,  "Reset to factory defaults",         true,  true  },
    { 12, CON_SHELL,    "Shell",                             false, false },
    { 13, CON_DESKTOP,  "Desktop console on the local screen", false, true  },
    { 14, CON_REBOOT,   "Reboot the system",                 true,  true  },
    { 15, CON_HALT,     "Halt the system",                   true,  true  },
};

#define N_ITEMS ((int)(sizeof(ITEMS) / sizeof(ITEMS[0])))

const console_item_t *console_items(int *count) {
    if (count) *count = N_ITEMS;
    return ITEMS;
}

const console_item_t *console_item_for(console_action_t a) {
    for (int i = 0; i < N_ITEMS; i++)
        if (ITEMS[i].action == a) return &ITEMS[i];
    return NULL;
}

console_action_t console_lookup(const char *input) {
    if (!input) return CON_INVALID;

    const char *s = input;
    while (*s == ' ' || *s == '\t') s++;
    if (!*s || *s == '\n' || *s == '\r') return CON_NONE;

    /*
     * The whole remaining line must be one number. Reading "5x" as 5 is
     * how a mistyped command turns into a reboot, so anything trailing is
     * a refusal rather than a prefix match.
     */
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s) return CON_INVALID;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r') end++;
    if (*end) return CON_INVALID;

    for (int i = 0; i < N_ITEMS; i++)
        if (ITEMS[i].choice == v) return ITEMS[i].action;
    return CON_INVALID;
}

/* ── rendering ──────────────────────────────────────────────── */

int console_slot_line(const slots_t *s, char *out, size_t outlen) {
    if (!s || !out) return -1;
    const slot_t *run = &s->slot[s->running];

    int n;
    if (s->next != s->running) {
        n = snprintf(out, outlen,
                     "slot %s (%s, %s) -- next boot: slot %s %s",
                     slot_name(s->running), run->version,
                     slot_state_name(run->state),
                     slot_name(s->next), s->slot[s->next].version);
    } else if (run->state == SLOT_PENDING) {
        n = snprintf(out, outlen,
                     "slot %s (%s) UNCONFIRMED -- %d boot attempt(s) left",
                     slot_name(s->running), run->version, run->tries_left);
    } else {
        n = snprintf(out, outlen, "slot %s (%s, %s)",
                     slot_name(s->running), run->version,
                     slot_state_name(run->state));
    }
    if (n < 0 || (size_t)n >= outlen) return -1;
    return n;
}

int console_render(char *out, size_t outlen,
                   const char *hostname, const char *version,
                   const slots_t *slots) {
    if (!out || outlen < 256) return -1;

    char slotline[160] = "";
    if (slots) console_slot_line(slots, slotline, sizeof(slotline));

    int n = snprintf(out, outlen,
        "\n"
        "*** %s by %s -- %s ***\n"
        "\n"
        "  %s\n"
        "%s%s%s"
        "\n",
        BRAND_PRODUCT, BRAND_VENDOR,
        version ? version : BRAND_VERSION,
        hostname ? hostname : "firex",
        slotline[0] ? "  " : "", slotline, slotline[0] ? "\n" : "");

    if (n < 0 || (size_t)n >= outlen) return -1;
    size_t used = (size_t)n;

    for (int i = 0; i < N_ITEMS; i++) {
        int w = snprintf(out + used, outlen - used, "  %2d) %s%s\n",
                         ITEMS[i].choice, ITEMS[i].label,
                         ITEMS[i].destructive ? "  *" : "");
        if (w < 0 || (size_t)w >= outlen - used) return -1;
        used += (size_t)w;
    }

    int w = snprintf(out + used, outlen - used,
                     "\n  * asks for confirmation before it does anything.\n"
                     "\nEnter an option: ");
    if (w < 0 || (size_t)w >= outlen - used) return -1;
    used += (size_t)w;
    return (int)used;
}

/* ── interactive helpers ────────────────────────────────────── */

static bool read_line(char *buf, size_t n) {
    if (!fgets(buf, (int)n, stdin)) return false;
    size_t l = strlen(buf);
    while (l && (buf[l - 1] == '\n' || buf[l - 1] == '\r')) buf[--l] = '\0';
    return true;
}

static bool confirm(const char *what) {
    char buf[64];
    printf("\n%s\nType YES to continue, anything else to cancel: ", what);
    fflush(stdout);
    if (!read_line(buf, sizeof(buf))) return false;
    return strcmp(buf, "YES") == 0;
}

/*
 * Operator-typed text that reaches a shell command is restricted to the
 * characters a hostname or an interface name can contain. A console user
 * is trusted, but a trusted user who pastes the wrong line should get an
 * error rather than a command substitution.
 */
/*
 * Reads a line with echo off. Falls back to echoing when the input is not
 * a terminal, which only happens in tests and scripts -- and says so,
 * rather than quietly showing a password on a real console.
 */
static bool read_secret(char *buf, size_t n) {
    struct termios old, quiet;
    bool restore = false;

    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old) == 0) {
        quiet = old;
        quiet.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0) restore = true;
    }

    bool got = read_line(buf, n);

    if (restore) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        printf("\n");
    }
    return got;
}

static bool plain_token(const char *s) {
    if (!s || !*s || strlen(s) > 64) return false;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' &&
            *p != '_' && *p != ':')
            return false;
    return true;
}

/* ── handlers ───────────────────────────────────────────────── */

static void show_status(console_ctx_t *c) {
    printf("\n--- %s status ---\n", BRAND_PRODUCT);
    if (c->vlan) {
        printf("  vlans           %d\n", c->vlan->vlan_count);
        printf("  ports           %d\n", c->vlan->port_count);
        printf("  acl rules       %d\n", c->vlan->ivr_count);
        printf("  inter-vlan      %lu allowed, %lu denied\n",
               c->vlan->inter_vlan_allowed, c->vlan->inter_vlan_denied);
        printf("  vlan violations %lu\n", c->vlan->vlan_violations);
    }
    if (c->netconf) {
        for (int i = 0; i < c->netconf->wan_count; i++) {
            wan_config_t *w = &c->netconf->wan[i];
            printf("  wan%-12d %s, link %s\n", i, w->ifname,
                   w->link_up ? "up" : "down");
        }
        printf("  port forwards   %d\n", c->netconf->forward_count);
        printf("  static routes   %d\n", c->netconf->route_count);
    }
    if (c->pkg) printf("  packages        %d installed\n", c->pkg->count);
    printf("  provisioning    %u failed command(s) since start\n",
           fx_run_failures());
    printf("\n");
}

static void show_ifaces(console_ctx_t *c) {
    printf("\n--- interface assignments ---\n");
    if (!c->vlan || c->vlan->port_count == 0) {
        printf("  (none configured)\n\n");
        return;
    }
    printf("  %-10s %-14s %-9s %-6s %s\n",
           "PORT", "LABEL", "MODE", "PVID", "LINK");
    for (int i = 0; i < c->vlan->port_count; i++) {
        port_config_t *p = &c->vlan->ports[i];
        printf("  %-10s %-14s %-9s %-6u %s\n",
               p->ifname, p->label, port_mode_name(p->mode), p->pvid,
               p->link_up ? "up" : "down");
    }
    printf("\n");
}

static void show_slots(console_ctx_t *c) {
    printf("\n--- A/B slots ---\n");
    if (!c->slots) { printf("  (slot state unavailable)\n\n"); return; }
    for (int i = 0; i < 2; i++) {
        const slot_t *s = &c->slots->slot[i];
        printf("  slot %s  %-8s %-10s tries %d  %s%s\n",
               slot_name((slot_id_t)i), s->version[0] ? s->version : "-",
               slot_state_name(s->state), s->tries_left, s->label,
               (slot_id_t)i == c->slots->running ? "   <- running" : "");
    }
    printf("  next boot: slot %s\n\n", slot_name(c->slots->next));
}

static void do_ping(void) {
    char host[128], cmd[256];
    printf("\nHost to ping: ");
    fflush(stdout);
    if (!read_line(host, sizeof(host))) return;
    if (!plain_token(host)) {
        printf("  '%s' is not a plain hostname or address.\n\n", host);
        return;
    }
    snprintf(cmd, sizeof(cmd), "ping -c 4 -w 8 %s", host);
    printf("\n");
    fx_try(cmd);
    printf("\n");
}

static void do_update(console_ctx_t *c) {
    char path[256];
    printf("\nPath to the signed update bundle: ");
    fflush(stdout);
    if (!read_line(path, sizeof(path))) return;
    if (!path[0]) return;

    upd_keyring_t ring;
    char err[256] = "";
    if (upd_keyring_load(&ring, c->keyring_path, err, sizeof(err)) != 0) {
        printf("  no usable keyring: %s\n\n", err);
        return;
    }

    upd_meta_t m;
    if (upd_bundle_verify(path, &ring, BRAND_VERSION, &m, err, sizeof(err)) != 0) {
        printf("  REJECTED: %s\n\n", err);
        return;
    }

    printf("\n  verified signature from key %s\n", m.signer);
    printf("  version      %s\n", m.version);
    printf("  built        %s\n", m.build);
    printf("  size         %llu bytes\n", (unsigned long long)m.size);
    printf("  description  %s\n", m.description[0] ? m.description : "(none)");

    if (m.kind == UPD_KIND_PACKAGE) {
        printf("\n  This is a package, not a system image. Use option 10.\n\n");
        return;
    }
    if (!c->slots) { printf("\n  slot state unavailable\n\n"); return; }

    slot_id_t target = slots_target(c->slots);
    printf("\n  It would be written to slot %s, replacing %s.\n",
           slot_name(target),
           c->slots->slot[target].version[0]
             ? c->slots->slot[target].version : "an unused slot");

    if (!confirm("Installing writes the inactive slot and selects it for the "
                 "next boot.\nThe running system is not touched.")) {
        printf("  cancelled\n\n");
        return;
    }

    char tmp[320];
    snprintf(tmp, sizeof(tmp), "/var/tmp/firex-slot-%s.img", slot_name(target));
    printf("\n  extracting the payload to %s ...\n", tmp);
    if (upd_bundle_extract(path, &ring, tmp, err, sizeof(err)) != 0) {
        printf("  failed: %s\n\n", err);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "dd if=%s of=/dev/disk/by-label/%s bs=4M "
             "conv=fsync status=progress", tmp, c->slots->slot[target].label);
    printf("  writing slot %s ...\n", slot_name(target));
    if (fx_run(cmd) != 0) {
        printf("\n  the write failed; slot %s is now unreliable and has NOT\n"
               "  been selected for boot. The running system is unchanged.\n\n",
               slot_name(target));
        c->slots->slot[target].state = SLOT_BAD;
        slots_save(c->slots, c->slots_path, NULL, 0);
        unlink(tmp);
        return;
    }
    unlink(tmp);

    slots_begin_update(c->slots, target, m.version, SLOT_DEFAULT_TRIES);
    if (slots_save(c->slots, c->slots_path, err, sizeof(err)) != 0) {
        printf("  the slot state could not be saved: %s\n\n", err);
        return;
    }

    char grub[4096];
    if (slots_grub_config(c->slots, grub, sizeof(grub)) > 0) {
        FILE *g = fopen("/boot/grub/grub.cfg", "w");
        if (g) { fputs(grub, g); fclose(g); }
        else   printf("  warning: /boot/grub/grub.cfg could not be written\n");
    }

    printf("\n  slot %s now holds %s and is selected for the next boot.\n"
           "  It has %d attempts to come up and confirm itself; if it does\n"
           "  not, the system returns to slot %s automatically.\n\n",
           slot_name(target), m.version, SLOT_DEFAULT_TRIES,
           slot_name(c->slots->running));
}

static void do_rollback(console_ctx_t *c) {
    char err[256] = "";
    if (!c->slots) { printf("\n  slot state unavailable\n\n"); return; }

    slot_id_t other = (c->slots->running == SLOT_A) ? SLOT_B : SLOT_A;
    printf("\n  Running slot %s (%s). The other slot holds %s (%s).\n",
           slot_name(c->slots->running), c->slots->slot[c->slots->running].version,
           c->slots->slot[other].version[0] ? c->slots->slot[other].version : "nothing",
           slot_state_name(c->slots->slot[other].state));

    if (c->slots->slot[other].state != SLOT_GOOD) {
        printf("  cannot roll back: slot %s is %s, not a working system.\n\n",
               slot_name(other), slot_state_name(c->slots->slot[other].state));
        return;
    }

    /* Confirm first: slots_rollback() demotes the slot being left, and a
     * cancel after the fact cannot put that back honestly. */
    if (!confirm("The next boot will use the other slot.")) {
        printf("  cancelled\n\n");
        return;
    }
    if (slots_rollback(c->slots, err, sizeof(err)) != 0) {
        printf("  cannot roll back: %s\n\n", err);
        return;
    }
    if (slots_save(c->slots, c->slots_path, err, sizeof(err)) != 0)
        printf("  could not save the slot state: %s\n\n", err);
    else
        printf("  done. Reboot (option 13) to take effect.\n\n");
}

static void do_packages(console_ctx_t *c) {
    if (!c->pkg) { printf("\n  package state unavailable\n\n"); return; }

    printf("\n--- packages ---\n");
    if (c->pkg->count == 0) printf("  (none installed)\n");
    for (int i = 0; i < c->pkg->count; i++)
        printf("  %-20s %-10s %s\n", c->pkg->pkg[i].name,
               c->pkg->pkg[i].version, c->pkg->pkg[i].description);

    printf("\n  i) install a bundle   r) remove a package   Enter) back\n  > ");
    fflush(stdout);

    char buf[256];
    if (!read_line(buf, sizeof(buf)) || !buf[0]) { printf("\n"); return; }

    char err[256] = "";
    if (buf[0] == 'i') {
        printf("  Path to the package bundle: ");
        fflush(stdout);
        if (!read_line(buf, sizeof(buf)) || !buf[0]) return;

        upd_keyring_t ring;
        if (upd_keyring_load(&ring, c->keyring_path, err, sizeof(err)) != 0) {
            printf("  no usable keyring: %s\n\n", err);
            return;
        }
        pkg_plan_t plan;
        if (pkg_install(c->pkg, buf, &ring, true, &plan, err, sizeof(err)) != 0) {
            printf("  REJECTED: %s\n\n", err);
            return;
        }
        printf("\n  it would run:\n");
        for (int i = 0; i < plan.count; i++) printf("    %s\n", plan.cmd[i]);
        if (!confirm("Install this package?")) { printf("  cancelled\n\n"); return; }

        if (pkg_install(c->pkg, buf, &ring, false, NULL, err, sizeof(err)) != 0)
            printf("  failed: %s\n\n", err);
        else
            printf("  installed\n\n");
    } else if (buf[0] == 'r') {
        printf("  Package to remove: ");
        fflush(stdout);
        if (!read_line(buf, sizeof(buf)) || !buf[0]) return;
        if (!plain_token(buf)) { printf("  not a package name\n\n"); return; }
        if (!confirm("Remove this package and the files it installed?")) {
            printf("  cancelled\n\n");
            return;
        }
        if (pkg_remove(c->pkg, buf, false, NULL, err, sizeof(err)) != 0)
            printf("  failed: %s\n\n", err);
        else
            printf("  removed\n\n");
    }
}

static void do_setip(void) {
    char iface[64], cidr[64], cmd[256];
    printf("\nInterface (for example eth1.10): ");
    fflush(stdout);
    if (!read_line(iface, sizeof(iface)) || !plain_token(iface)) {
        printf("  not an interface name\n\n");
        return;
    }
    printf("Address with prefix (for example 10.10.10.1/24): ");
    fflush(stdout);
    if (!read_line(cidr, sizeof(cidr))) return;
    /* plain_token rejects '/', so check the address form separately. */
    for (const char *p = cidr; *p; p++)
        if (!isdigit((unsigned char)*p) && *p != '.' && *p != '/' && *p != ':') {
            printf("  '%s' is not an address\n\n", cidr);
            return;
        }
    if (!cidr[0] || !strchr(cidr, '/')) {
        printf("  the address needs a /prefix\n\n");
        return;
    }

    snprintf(cmd, sizeof(cmd), "ip addr flush dev %s", iface);
    fx_try(cmd);
    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", cidr, iface);
    if (fx_run(cmd) != 0) { printf("  failed\n\n"); return; }
    snprintf(cmd, sizeof(cmd), "ip link set %s up", iface);
    fx_run(cmd);
    printf("  %s is now %s\n"
           "  This is a running change only; it is not written to %s.\n\n",
           iface, cidr, BRAND_CONFIG_DIR "/firex.conf");
}

/*
 * The GUI runs on the appliance's own monitor, not down this serial
 * line, so this starts the service rather than trying to draw anything
 * here. Saying where it went matters: somebody on a serial cable who
 * picks this and sees nothing happen will assume it is broken.
 */
static void do_desktop(void) {
    printf("\n");

    if (access("/usr/local/bin/flamewall", X_OK) != 0) {
        printf("  The desktop console is not installed in this image.\n"
               "  It is left out by building with FIREX_DESKTOP=0.\n"
               "  Use the web console instead: http://<appliance>:8080/ui\n\n");
        return;
    }

    printf("  The desktop console opens on this machine's own monitor,\n"
           "  not on this serial line. It signs in with the same account\n"
           "  you used here.\n\n");

    if (!confirm("Start it on the local screen now?")) {
        printf("  cancelled\n\n");
        return;
    }

    /* restart, not start: picking this twice should put a fresh console
     * on the screen rather than report that one is already running. */
    if (fx_run("systemctl restart firex-gui.service") == 0)
        printf("\n  started. Look at the appliance's screen.\n"
               "  Nothing there?  firex-gui --check\n\n");
    else
        printf("\n  could not start it. Run:  firex-gui --check\n\n");
}

static void do_passwd(console_ctx_t *c) {
    char user[64], pass[128], again[128];

    if (!c->users_path) { printf("\n  no user database configured\n\n"); return; }

    printf("\nUser to set a password for (Enter for 'admin'): ");
    fflush(stdout);
    if (!read_line(user, sizeof(user))) return;
    if (!user[0]) snprintf(user, sizeof(user), "admin");
    if (!plain_token(user)) { printf("  '%s' is not a user name\n\n", user); return; }

    printf("New password: ");
    fflush(stdout);
    if (!read_secret(pass, sizeof(pass))) return;
    printf("Repeat: ");
    fflush(stdout);
    if (!read_secret(again, sizeof(again))) return;

    bool match = strcmp(pass, again) == 0;
    explicit_bzero(again, sizeof(again));
    if (!match) {
        printf("  the passwords do not match\n\n");
        explicit_bzero(pass, sizeof(pass));
        return;
    }
    if (strlen(pass) < 8) {
        printf("  the password must be at least 8 characters\n\n");
        explicit_bzero(pass, sizeof(pass));
        return;
    }

    auth_ctx_t a;
    if (auth_load_quiet(&a, c->users_path) != 0) {
        printf("  cannot use %s\n\n", c->users_path);
        explicit_bzero(pass, sizeof(pass));
        return;
    }
    bool existed = false;
    for (int i = 0; i < a.user_count; i++)
        if (!strcmp(a.users[i].name, user)) existed = true;

    int rc = existed ? auth_set_password(&a, user, pass)
                     : auth_add_user(&a, user, pass, ROLE_ADMIN);
    explicit_bzero(pass, sizeof(pass));

    if (rc != 0) printf("  could not write %s\n\n", c->users_path);
    else printf("  %s '%s'\n\n", existed ? "password changed for" : "created", user);
}

/* ── login ──────────────────────────────────────────────────── */

#define CONSOLE_LOGIN_TRIES 3

/*
 * The appliance ships with root/root and admin/admin so it is always
 * reachable. Whoever just signed in is the person who can fix that, and
 * the serial console is often the only place anyone looks -- so it says
 * so here as well as on every page of the web console.
 */
static void warn_shipped_credentials(auth_ctx_t *a) {
    auth_entry_t list[AUTH_MAX_USERS];
    int n = auth_list(a, list, AUTH_MAX_USERS);

    char names[256];
    size_t o = 0;
    int defaults = 0;

    for (int i = 0; i < n; i++) {
        bool sys_default = (auth_system_state(list[i].name) == 1);
        if (!list[i].is_default && !sys_default) continue;
        defaults++;
        if (o < sizeof(names) - 40)
            o += (size_t)snprintf(names + o, sizeof(names) - o, "%s%s",
                                  o ? ", " : "", list[i].name);
    }
    if (defaults == 0) return;

    printf("\n"
           "  !! %s still on the shipped password: %s\n"
           "     Change it here with option 4, or in the web console\n"
           "     under System.\n",
           defaults == 1 ? "One account is" : "Accounts are", names);
}

int console_login(console_ctx_t *ctx) {
    if (!ctx || !ctx->users_path) return 0;

    auth_ctx_t a;
    /*
     * Deliberately not auth_init(): that bootstraps an admin account when
     * the database is missing and prints its password. Done here, anyone
     * who reaches the serial port could delete the database, reconnect,
     * and be handed fresh credentials. Creating accounts is the daemon's
     * job; the console only ever reads them.
     */
    if (auth_load_quiet(&a, ctx->users_path) != 0 || a.user_count == 0) {
        printf("\n  WARNING: no console users are configured in %s.\n"
               "  This menu is open to anyone with access to the serial\n"
               "  port. Set a password before putting this appliance into\n"
               "  service.\n", ctx->users_path);
        return 0;
    }

    for (int tries = 0; tries < CONSOLE_LOGIN_TRIES; tries++) {
        char user[64], pass[128];

        printf("\n%s login: ", ctx->hostname ? ctx->hostname : BRAND_PRODUCT);
        fflush(stdout);
        if (!read_line(user, sizeof(user))) return -1;

        printf("Password: ");
        fflush(stdout);
        if (!read_secret(pass, sizeof(pass))) return -1;

        fx_session_t sess;
        /* 127.0.0.1 as the peer: the throttle is per source address, and
         * the console is as local as a request gets. */
        int rc = auth_login(&a, user, pass, htonl(0x7f000001), &sess);
        explicit_bzero(pass, sizeof(pass));

        if (rc == 0) {
            printf("\n  Welcome, %s.\n", sess.user);
            warn_shipped_credentials(&a);
            return 0;
        }
        if (rc == -2) {
            printf("\n  Too many failed attempts. Try again later.\n");
            return -1;
        }
        printf("  Login incorrect.\n");
    }
    return -1;
}

/* ── the loop ───────────────────────────────────────────────── */

int console_run(console_ctx_t *ctx) {
    if (!ctx) return -1;
    char menu[4096], line[128];

    if (console_login(ctx) != 0) return -1;

    for (;;) {
        if (console_render(menu, sizeof(menu), ctx->hostname,
                           BRAND_VERSION, ctx->slots) < 0)
            return -1;
        fputs(menu, stdout);
        fflush(stdout);

        if (!read_line(line, sizeof(line))) {    /* Ctrl-D */
            printf("\n");
            return 0;
        }

        console_action_t a = console_lookup(line);
        if (a == CON_NONE) continue;
        if (a == CON_INVALID) {
            printf("\n  '%s' is not one of the options.\n", line);
            continue;
        }

        const console_item_t *it = console_item_for(a);
        if (it && it->needs_root && geteuid() != 0) {
            printf("\n  '%s' needs root. Re-run the console as root.\n\n",
                   it->label);
            continue;
        }

        switch (a) {
            case CON_LOGOUT:   return 0;
            case CON_STATUS:   show_status(ctx);  break;
            case CON_IFACES:   show_ifaces(ctx);  break;
            case CON_SLOTS:    show_slots(ctx);   break;
            case CON_PING:     do_ping();         break;
            case CON_SETIP:    do_setip();        break;
            case CON_UPDATE:   do_update(ctx);    break;
            case CON_ROLLBACK: do_rollback(ctx);  break;
            case CON_PACKAGES: do_packages(ctx);  break;

            case CON_PASSWD:   do_passwd(ctx);    break;
            case CON_DESKTOP:  do_desktop();      break;

            case CON_RELOAD:
                printf("\n  reloading ...\n");
                fx_run("systemctl reload firexd");
                printf("\n");
                break;

            case CON_FACTORY:
                if (confirm("This erases the configuration and every saved "
                            "revision.\nThe other boot slot is not touched.")) {
                    char cmd[256];
                    snprintf(cmd, sizeof(cmd), "rm -rf %s/config.d",
                             BRAND_CONFIG_DIR);
                    fx_run(cmd);
                    printf("  configuration revisions cleared. Reboot to "
                           "rebuild from defaults.\n\n");
                } else printf("  cancelled\n\n");
                break;

            case CON_SHELL:
                printf("\n  Type 'exit' to come back to this menu.\n\n");
                fx_try("/bin/sh -i");
                break;

            case CON_REBOOT:
                if (confirm("Reboot now?")) fx_run("systemctl reboot");
                else printf("  cancelled\n\n");
                break;

            case CON_HALT:
                if (confirm("Halt now? The appliance will stop forwarding "
                            "traffic.")) fx_run("systemctl poweroff");
                else printf("  cancelled\n\n");
                break;

            default: break;
        }
    }
}
