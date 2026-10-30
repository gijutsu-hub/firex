/*
 * A/B root slots.
 *
 * Two root filesystems. One is running; updates are written to the other.
 * A freshly written slot is PENDING with a budget of boot attempts: the
 * running system spends one on every boot and only clears the state by
 * calling slots_confirm() once it is far enough up to be trusted. A slot
 * that never confirms runs out of budget and is marked BAD, and the
 * bootloader is pointed back at the slot that was working.
 *
 * That is the whole safety property: an update that does not reach a
 * working firexd cannot keep the appliance off the network, because
 * nothing ever erases the slot that is currently serving traffic.
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "update.h"
#include "brand.h"

#define ERRF(e, n, ...) do { if (e && n) snprintf(e, n, __VA_ARGS__); } while (0)

const char *slot_name(slot_id_t id) { return id == SLOT_B ? "b" : "a"; }

const char *slot_state_name(slot_state_t st) {
    switch (st) {
        case SLOT_PENDING: return "pending";
        case SLOT_GOOD:    return "good";
        case SLOT_BAD:     return "bad";
        default:           return "unused";
    }
}

static slot_state_t state_from(const char *s) {
    if (!strcmp(s, "pending")) return SLOT_PENDING;
    if (!strcmp(s, "good"))    return SLOT_GOOD;
    if (!strcmp(s, "bad"))     return SLOT_BAD;
    return SLOT_UNUSED;
}

void slots_init(slots_t *s) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < 2; i++) {
        s->slot[i].state = SLOT_UNUSED;
        snprintf(s->slot[i].label, sizeof(s->slot[i].label),
                 "firex-root-%s", slot_name((slot_id_t)i));
    }
    /*
     * A machine that has never been updated is running slot A from the
     * factory image, and that image did boot -- it is running. Calling
     * it GOOD from the start means a first update always has a sound
     * slot to fall back to.
     */
    s->slot[SLOT_A].state = SLOT_GOOD;
    snprintf(s->slot[SLOT_A].version, sizeof(s->slot[SLOT_A].version),
             "%s", BRAND_VERSION);
    s->running = SLOT_A;
    s->next    = SLOT_A;
}

slot_id_t slots_target(const slots_t *s) {
    return s->running == SLOT_A ? SLOT_B : SLOT_A;
}

/* ── persistence ────────────────────────────────────────────── */

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
                     e[-1] == ' '  || e[-1] == '\t')) *--e = '\0';
    return s;
}

int slots_load(slots_t *s, const char *path, char *err, size_t errlen) {
    if (!s) return -1;
    slots_init(s);

    FILE *f = fopen(path, "r");
    if (!f) {
        /*
         * No state file is the normal first boot, not a failure: the
         * defaults describe exactly that machine. Say so and carry on.
         */
        ERRF(err, errlen, "%s: %s (using defaults)", path, strerror(errno));
        return 1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (!*p || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(p), *val = trim(eq + 1);

        if (!strcmp(key, "running")) { s->running = (*val == 'b') ? SLOT_B : SLOT_A; continue; }
        if (!strcmp(key, "next"))    { s->next    = (*val == 'b') ? SLOT_B : SLOT_A; continue; }

        /* "a.state", "b.version", ... */
        if ((key[0] != 'a' && key[0] != 'b') || key[1] != '.') continue;
        slot_t *sl = &s->slot[key[0] == 'b' ? SLOT_B : SLOT_A];
        const char *f2 = key + 2;

        if      (!strcmp(f2, "state"))   sl->state = state_from(val);
        else if (!strcmp(f2, "version")) snprintf(sl->version, sizeof(sl->version), "%s", val);
        else if (!strcmp(f2, "label"))   snprintf(sl->label, sizeof(sl->label), "%s", val);
        else if (!strcmp(f2, "tries"))   sl->tries_left = atoi(val);
        else if (!strcmp(f2, "installed")) sl->installed = strtoull(val, NULL, 10);
    }
    fclose(f);
    return 0;
}

int slots_save(const slots_t *s, const char *path, char *err, size_t errlen) {
    if (!s) return -1;

    /*
     * Written to a temporary and renamed: a machine that loses power
     * during this must come back to either the old state or the new one,
     * never to a half-written file that decides which root it boots.
     */
    char tmp[512];
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= sizeof(tmp)) {
        ERRF(err, errlen, "%s: path too long", path);
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { ERRF(err, errlen, "%s: %s", tmp, strerror(errno)); return -1; }
    FILE *f = fdopen(fd, "w");
    if (!f) { ERRF(err, errlen, "%s: %s", tmp, strerror(errno)); close(fd); return -1; }

    fprintf(f, "# %s A/B slot state -- written by firexd, do not hand-edit\n",
            BRAND_PRODUCT);
    fprintf(f, "running = %s\n", slot_name(s->running));
    fprintf(f, "next = %s\n\n", slot_name(s->next));
    for (int i = 0; i < 2; i++) {
        const slot_t *sl = &s->slot[i];
        const char *n = slot_name((slot_id_t)i);
        fprintf(f, "%s.state = %s\n",     n, slot_state_name(sl->state));
        fprintf(f, "%s.version = %s\n",   n, sl->version);
        fprintf(f, "%s.label = %s\n",     n, sl->label);
        fprintf(f, "%s.tries = %d\n",     n, sl->tries_left);
        fprintf(f, "%s.installed = %llu\n\n", n, (unsigned long long)sl->installed);
    }

    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        ERRF(err, errlen, "%s: %s", tmp, strerror(errno));
        fclose(f); unlink(tmp);
        return -1;
    }
    fclose(f);

    if (rename(tmp, path) != 0) {
        ERRF(err, errlen, "%s: %s", path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* ── lifecycle ──────────────────────────────────────────────── */

int slots_begin_update(slots_t *s, slot_id_t id, const char *version, int tries) {
    if (!s) return -1;
    if (id == s->running) return -1;   /* never overwrite the running root */

    slot_t *sl = &s->slot[id];
    sl->state      = SLOT_PENDING;
    sl->tries_left = tries > 0 ? tries : SLOT_DEFAULT_TRIES;
    sl->installed  = (uint64_t)time(NULL);
    snprintf(sl->version, sizeof(sl->version), "%s", version ? version : "");
    s->next = id;
    return 0;
}

bool slots_boot_attempt(slots_t *s) {
    if (!s) return false;
    slot_t *run = &s->slot[s->running];

    if (run->state != SLOT_PENDING) return false;

    if (run->tries_left > 0) run->tries_left--;
    if (run->tries_left > 0) {
        /* Still has attempts left; stay here and hope confirm arrives. */
        s->next = s->running;
        return false;
    }

    /* Budget exhausted without a confirm: this slot does not work. */
    run->state = SLOT_BAD;
    slot_id_t other = (s->running == SLOT_A) ? SLOT_B : SLOT_A;
    if (s->slot[other].state == SLOT_GOOD) {
        s->next = other;
        return true;
    }
    /*
     * Both slots are unusable. Pointing next at a bad slot changes
     * nothing, so stay put: a running system that is marked bad is
     * still better than a deliberate reboot into one that is too.
     */
    s->next = s->running;
    return false;
}

int slots_confirm(slots_t *s) {
    if (!s) return -1;
    slot_t *run = &s->slot[s->running];
    run->state      = SLOT_GOOD;
    run->tries_left = 0;
    s->next         = s->running;
    return 0;
}

int slots_rollback(slots_t *s, char *err, size_t errlen) {
    if (!s) return -1;
    slot_id_t other = (s->running == SLOT_A) ? SLOT_B : SLOT_A;

    if (s->slot[other].state != SLOT_GOOD) {
        ERRF(err, errlen, "slot %s is %s, not a working system to roll back to",
             slot_name(other), slot_state_name(s->slot[other].state));
        return -1;
    }
    /* The slot being left is demoted, or the next boot would come back. */
    if (s->slot[s->running].state == SLOT_PENDING)
        s->slot[s->running].state = SLOT_BAD;
    s->next = other;
    return 0;
}

/* ── bootloader ─────────────────────────────────────────────── */

/*
 * snprintf returns what it WOULD have written, so advancing a cursor by
 * its return value walks past the end of the buffer on truncation and
 * turns the next (end - p) into a huge size_t. Everything below goes
 * through this instead, which saturates at the end and reports it.
 */
static bool app(char **p, char *end, const char *fmt, ...) {
    if (*p >= end) return false;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(*p, (size_t)(end - *p), fmt, ap);
    va_end(ap);
    if (n < 0 || n >= end - *p) { *p = end; return false; }
    *p += n;
    return true;
}

/*
 * Whether the generated entries ask for the Plymouth splash.
 *
 * grub.cfg is rewritten from four places -- the image build, an update,
 * the console menu and the boot-check fallback -- and every one of them
 * has to produce the same kernel line, or a rollback would silently drop
 * the splash. A process-wide setting keeps that in one place instead of
 * threading a flag through four call sites that have no opinion on it.
 */
static bool g_splash = true;

void slots_set_splash(bool on) { g_splash = on; }

/*
 * The video mode GRUB sets before handing control to the kernel. It is
 * also the framebuffer Plymouth draws on and the one Xorg inherits, so
 * the desktop console's fixed screen size starts here -- set it in only
 * one of the three and the GUI comes up letterboxed.
 */
static char g_gfxmode[64] = "1024x768,800x600,auto";

void slots_set_gfxmode(const char *mode) {
    if (!mode || !*mode) return;
    /* Appended to a list, so a mode that is not WxH would make the whole
     * `set gfxmode=` line unparseable and cost the graphical menu. */
    int w = 0, h = 0;
    char tail = 0;
    if (sscanf(mode, "%dx%d%c", &w, &h, &tail) != 2 || w < 320 || h < 240) return;
    snprintf(g_gfxmode, sizeof(g_gfxmode), "%dx%d,1024x768,800x600,auto", w, h);
}

static bool grub_entry(char **p, char *end, const slots_t *s, slot_id_t id) {
    const slot_t *sl = &s->slot[id];
    return app(p, end,
        "menuentry '%s %s (slot %s, %s)' {\n"
        "    search --no-floppy --label --set=root %s\n"
        "    linux /boot/vmlinuz root=LABEL=%s ro firex.slot=%s "
        /*
         * Classic interface names, because the shipped configuration is
         * written in them: firex.conf names eth0 as the WAN and eth1 as
         * the trunk, and every [port:ethN] stanza keys off that.
         *
         * With predictable naming left on, the same appliance comes up
         * with enp0s3 and enp0s8 instead, every port stanza misses, and
         * the result is an appliance that boots perfectly and segments
         * nothing -- no error anywhere, because a port that is not in the
         * configuration is not a fault, it is just a port nobody
         * mentioned. /etc/default/grub carries these two as well, but
         * nothing reads that file here: this generator writes grub.cfg
         * itself, so the setting has to be on this line to have any
         * effect at all.
         */
        "net.ifnames=0 biosdevname=0 "
        /*
         * tty0 is named LAST on purpose. The kernel makes the last
         * console= the one behind /dev/console, and Plymouth follows
         * /dev/console: with ttyS0 last it renders as text down the
         * serial line and the screen stays blank. Both consoles still
         * receive every kernel message either way.
         *
         * Ordering is not enough on its own, though. Plymouth also scans
         * for serial consoles and, finding one, gives up on the splash
         * and prints the boot log instead -- which is exactly what this
         * appliance got: a screen of white-on-black systemd lines where
         * the logo should have been, on a machine whose framebuffer was
         * working the whole time. plymouth.ignore-serial-consoles tells
         * it to leave ttyS0 to the serial getty and draw on the screen.
         */
        "console=ttyS0,115200n8 console=tty0%s\n"
        "    initrd /boot/initrd.img\n"
        "}\n",
        BRAND_PRODUCT, sl->version[0] ? sl->version : "unknown",
        slot_name(id), slot_state_name(sl->state),
        sl->label, sl->label, slot_name(id),
        g_splash ? " quiet splash plymouth.ignore-serial-consoles" : "");
}

int slots_grub_config(const slots_t *s, char *out, size_t outlen) {
    if (!s || !out || outlen < 256) return -1;

    char *p = out, *end = out + outlen;
    slot_id_t first  = s->next;
    slot_id_t second = (first == SLOT_A) ? SLOT_B : SLOT_A;

    bool ok = app(&p, end,
        "# Generated by %s %s -- rewritten on every update, do not edit.\n"
        "# The preferred slot is listed first, so default=0 always selects it.\n"
        "set timeout=5\n"
        "set default=0\n"
        "serial --unit=0 --speed=115200\n"
        "terminal_input console serial\n"
        "terminal_output console serial\n"
        "\n"
        "# Graphical menu. Every step is guarded and the plain text menu is\n"
        "# already selected above, so a missing font, theme or video driver\n"
        "# costs the artwork and nothing else -- the appliance still boots.\n"
        "insmod all_video\n"
        "insmod gfxterm\n"
        "insmod png\n"
        "set gfxmode=%s\n"
        "set gfxpayload=keep\n"
        "if loadfont $prefix/fonts/unicode.pf2 ; then\n"
        "    if [ -f $prefix/themes/%s/theme.txt ] ; then\n"
        "        set theme=$prefix/themes/%s/theme.txt\n"
        "        export theme\n"
        "    fi\n"
        "    terminal_output gfxterm serial\n"
        "fi\n\n",
        BRAND_PRODUCT, BRAND_VERSION, g_gfxmode,
        BRAND_HOSTNAME, BRAND_HOSTNAME);

    ok = grub_entry(&p, end, s, first) && ok;
    ok = app(&p, end, "\n") && ok;
    ok = grub_entry(&p, end, s, second) && ok;

    if (!ok) return -1;          /* the caller's buffer was too small */
    return (int)(p - out);
}
