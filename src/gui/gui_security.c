/*
 * The desktop console's security page: live malware protection, the air
 * gap, and the kernel's interfaces.
 *
 * These three engines existed for a while with no presence here at all --
 * they were built into the daemon and surfaced only in the web console.
 * That is the wrong way round for an appliance. The screen attached to the
 * box is the one an operator reaches for when the network is the thing
 * that is broken, which is exactly when a browser on another machine is
 * not an option.
 *
 * Like the dashboard, everything here is read from the running daemon over
 * the same HTTP API the browser uses, so the two cannot disagree.
 */
#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>

#include "guiapp.h"
#include "brand.h"

#define SEC_REFRESH_SECONDS 5

typedef struct {
    fx_client_t *client;

    GtkWidget *mw_tiles;
    GtkWidget *mw_gaps;
    GtkWidget *ag_tiles;
    GtkWidget *ag_egress;
    GtkWidget *ifaces;
    GtkWidget *status;

    guint      timer;
} sec_t;

/* ── shared builders, kept in step with gui_dashboard.c ─────────────── */

static void clear(GtkWidget *box) {
    GtkWidget *c;
    while ((c = gtk_widget_get_first_child(box)))
        gtk_box_remove(GTK_BOX(box), c);
}

static GtkWidget *tile(const char *label, const char *value, const char *cls) {
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_add_css_class(b, "dash-tile");
    gtk_widget_set_hexpand(b, TRUE);

    GtkWidget *v = gtk_label_new(value);
    gtk_widget_add_css_class(v, "dash-num");
    if (cls) gtk_widget_add_css_class(v, cls);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0);

    GtkWidget *l = gtk_label_new(label);
    gtk_widget_add_css_class(l, "dash-lab");
    gtk_label_set_xalign(GTK_LABEL(l), 0.0);

    gtk_box_append(GTK_BOX(b), v);
    gtk_box_append(GTK_BOX(b), l);
    return b;
}

static GtkWidget *cell(const char *text, const char *cls, int width) {
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0);
    gtk_widget_add_css_class(l, cls ? cls : "dash-cell");
    if (width > 0) gtk_widget_set_size_request(l, width, -1);
    gtk_label_set_ellipsize(GTK_LABEL(l), PANGO_ELLIPSIZE_END);
    return l;
}

static GtkWidget *section(const char *title, GtkWidget *body) {
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(b, "dash-card");

    GtkWidget *t = gtk_label_new(title);
    gtk_widget_add_css_class(t, "dash-head");
    gtk_label_set_xalign(GTK_LABEL(t), 0.0);

    gtk_box_append(GTK_BOX(b), t);
    gtk_box_append(GTK_BOX(b), body);
    return b;
}

static GtkWidget *row(void) {
    GtkWidget *r = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    return r;
}

/* ── malware ────────────────────────────────────────────────────────── */

static void load_malware(sec_t *s) {
    clear(s->mw_tiles);
    clear(s->mw_gaps);

    char err[FXC_ERR_LEN] = "";
    char *j = fxc_get(s->client, "/api/malware", err, sizeof(err));
    if (!j) {
        gtk_box_append(GTK_BOX(s->mw_tiles),
                       tile("scanner", err[0] ? err : "unavailable", "dash-bad"));
        return;
    }

    double en = 0, bl = 0, det = 0, obj = 0, hashes = 0;
    fxj_num(j, "enabled", &en);
    fxj_num(j, "block",   &bl);
    fxj_num(j, "detections", &det);
    fxj_num(j, "objects", &obj);
    fxj_num(j, "hashes",  &hashes);

    /*
     * Coverage decides the headline, not the enabled flag.
     *
     * Scanning is set per segment. An engine that is on, blocking, with a
     * loaded database, over a network where no segment has scanning
     * switched on, inspects nothing -- and saying "ON" for that appliance
     * is a control reporting success it is not delivering. So the state
     * shown is the AND of the two.
     */
    const char *cov = strstr(j, "\"coverage\"");
    double segs = 0, on = 0;
    if (cov) {
        fxj_num(cov, "segments", &segs);
        fxj_num(cov, "segments_scanned", &on);
    }

    const char *head = !en ? "OFF" : (on < 1 ? "NO COVERAGE" : (bl ? "ON" : "DETECT"));
    const char *hcls = !en ? "dash-bad"
                           : (on < 1 ? "dash-bad" : (bl ? "dash-ok" : "dash-warn"));
    gtk_box_append(GTK_BOX(s->mw_tiles), tile("Protection", head, hcls));

    char v[64];
    snprintf(v, sizeof(v), "%d / %d", (int)on, (int)segs);
    gtk_box_append(GTK_BOX(s->mw_tiles),
                   tile("Segments covered", v,
                        (segs > 0 && on >= segs) ? "dash-ok" : "dash-warn"));

    snprintf(v, sizeof(v), "%lld", (long long)det);
    gtk_box_append(GTK_BOX(s->mw_tiles),
                   tile("Detections", v, det > 0 ? "dash-bad" : NULL));

    snprintf(v, sizeof(v), "%lld", (long long)obj);
    gtk_box_append(GTK_BOX(s->mw_tiles), tile("Objects scanned", v, NULL));

    snprintf(v, sizeof(v), "%lld", (long long)hashes);
    gtk_box_append(GTK_BOX(s->mw_tiles), tile("Signatures", v, NULL));

    /* The segments that are NOT scanned, by name. A count alone tells an
     * operator that something is uncovered without telling them what to
     * go and change. */
    if (en && on < 1) {
        gtk_box_append(GTK_BOX(s->mw_gaps),
            cell("The scanner is running but no segment is scanned, so no "
                 "transfer on this appliance is being inspected.",
                 "dash-bad", -1));
    }

    const char *p = cov ? fxj_array(cov, "uncovered") : NULL;
    int listed = 0;
    for (; p; p = fxj_next(p)) {
        char name[64] = "";
        double vid = 0;
        fxj_str(p, "name", name, sizeof(name));
        fxj_num(p, "vlan", &vid);

        GtkWidget *r = row();
        gtk_box_append(GTK_BOX(r), cell(name, "dash-cell", 160));
        snprintf(v, sizeof(v), "VLAN %d", (int)vid);
        gtk_box_append(GTK_BOX(r), cell(v, "dash-cell", 100));
        gtk_box_append(GTK_BOX(r), cell("not scanned", "dash-bad", -1));
        gtk_box_append(GTK_BOX(s->mw_gaps), r);
        listed++;
    }
    if (!listed && !(en && on < 1))
        gtk_box_append(GTK_BOX(s->mw_gaps),
                       cell("Every configured segment is scanned.", "dash-ok", -1));

    free(j);
}

/* ── air gap ────────────────────────────────────────────────────────── */

static void load_airgap(sec_t *s) {
    clear(s->ag_tiles);
    clear(s->ag_egress);

    char err[FXC_ERR_LEN] = "";
    char *j = fxc_get(s->client, "/api/airgap", err, sizeof(err));
    if (!j) {
        gtk_box_append(GTK_BOX(s->ag_tiles),
                       tile("boundary", err[0] ? err : "unavailable", "dash-bad"));
        return;
    }

    char label[64] = "", mode[32] = "", reason[192] = "";
    fxj_str(j, "label",  label,  sizeof(label));
    fxj_str(j, "mode",   mode,   sizeof(mode));
    fxj_str(j, "reason", reason, sizeof(reason));

    double open = 0, din = 0, dout = 0, fetches = 0;
    fxj_num(j, "open", &open);
    fxj_num(j, "denied_in",  &din);
    fxj_num(j, "denied_out", &dout);
    fxj_num(j, "blocked_fetches", &fetches);

    const char *connected = !strcmp(mode, "connected") ? "yes" : "no";
    gtk_box_append(GTK_BOX(s->ag_tiles),
                   tile("Boundary", open ? "OPEN" : "SHUT",
                        !strcmp(connected, "yes") ? "dash-ok"
                                                  : (open ? "dash-warn" : "dash-bad")));
    gtk_box_append(GTK_BOX(s->ag_tiles), tile("Mode", label[0] ? label : mode, NULL));

    char v[64];
    snprintf(v, sizeof(v), "%lld", (long long)dout);
    gtk_box_append(GTK_BOX(s->ag_tiles), tile("Denied outbound", v, NULL));
    snprintf(v, sizeof(v), "%lld", (long long)din);
    gtk_box_append(GTK_BOX(s->ag_tiles), tile("Denied inbound", v, NULL));
    snprintf(v, sizeof(v), "%lld", (long long)fetches);
    gtk_box_append(GTK_BOX(s->ag_tiles),
                   tile("Own fetches refused", v, fetches > 0 ? "dash-warn" : NULL));

    if (reason[0])
        gtk_box_append(GTK_BOX(s->ag_egress), cell(reason, "dash-cell", -1));

    /*
     * The appliance's own outbound traffic, per subsystem. This column is
     * what separates an air gap from a strict firewall, and a row reading
     * zero while the gap is shut is the signal that something is not being
     * gated -- which is why every subsystem is listed rather than only the
     * busy ones.
     */
    static const struct { const char *key, *what; } WHAT[] = {
        { "feeds",     "Reputation and blocklist refreshes" },
        { "telemetry", "Syslog and NetFlow to your collectors" },
        { "ha",        "Configuration push to the standby node" },
        { "gwmon",     "Gateway reachability probes" },
        { NULL, NULL }
    };

    for (const char *p = fxj_array(j, "egress"); p; p = fxj_next(p)) {
        char sub[32] = "";
        double refused = 0;
        fxj_str(p, "subsystem", sub, sizeof(sub));
        fxj_num(p, "refused", &refused);

        const char *what = "";
        for (int i = 0; WHAT[i].key; i++)
            if (!strcmp(WHAT[i].key, sub)) { what = WHAT[i].what; break; }

        GtkWidget *r = row();
        gtk_box_append(GTK_BOX(r), cell(sub, "dash-cell", 110));
        gtk_box_append(GTK_BOX(r), cell(what, "dash-cell", 300));
        snprintf(v, sizeof(v), "%lld refused", (long long)refused);
        gtk_box_append(GTK_BOX(r),
                       cell(v, refused > 0 ? "dash-warn" : "dash-cell", -1));
        gtk_box_append(GTK_BOX(s->ag_egress), r);
    }

    free(j);
}

/* ── interfaces ─────────────────────────────────────────────────────── */

static void load_interfaces(sec_t *s) {
    clear(s->ifaces);

    char err[FXC_ERR_LEN] = "";
    char *j = fxc_get(s->client, "/api/interfaces", err, sizeof(err));
    if (!j) {
        gtk_box_append(GTK_BOX(s->ifaces),
                       cell(err[0] ? err : "unavailable", "dash-bad", -1));
        return;
    }

    GtkWidget *hdr = row();
    gtk_box_append(GTK_BOX(hdr), cell("Interface", "dash-th", 120));
    gtk_box_append(GTK_BOX(hdr), cell("State",     "dash-th", 110));
    gtk_box_append(GTK_BOX(hdr), cell("Address",   "dash-th", 170));
    gtk_box_append(GTK_BOX(hdr), cell("Speed",     "dash-th", -1));
    gtk_box_append(GTK_BOX(s->ifaces), hdr);

    int n = 0;
    for (const char *p = fxj_array(j, "interfaces"); p; p = fxj_next(p)) {
        char name[48] = "", addr[64] = "";
        double up = 0, carrier = 0, speed = 0;
        fxj_str(p, "name", name, sizeof(name));
        fxj_str(p, "address", addr, sizeof(addr));
        fxj_num(p, "admin_up", &up);
        fxj_num(p, "carrier",  &carrier);
        fxj_num(p, "speed",    &speed);

        /*
         * Admin state and carrier are different facts and an operator
         * standing at the appliance needs both: "up but no carrier" means
         * go and look at the cable, "down" means somebody turned it off.
         */
        const char *st  = !up ? "down" : (carrier ? "up" : "no carrier");
        const char *cls = !up ? "dash-cell" : (carrier ? "dash-ok" : "dash-warn");

        char sp[32] = "-";
        if (speed > 0) snprintf(sp, sizeof(sp), "%d Mb/s", (int)speed);

        GtkWidget *r = row();
        gtk_box_append(GTK_BOX(r), cell(name, "dash-cell", 120));
        gtk_box_append(GTK_BOX(r), cell(st, cls, 110));
        gtk_box_append(GTK_BOX(r), cell(addr[0] ? addr : "-", "dash-cell", 170));
        gtk_box_append(GTK_BOX(r), cell(sp, "dash-cell", -1));
        gtk_box_append(GTK_BOX(s->ifaces), r);
        n++;
    }
    if (!n)
        gtk_box_append(GTK_BOX(s->ifaces),
                       cell("No interfaces reported.", "dash-cell", -1));

    free(j);
}

/* ── page ───────────────────────────────────────────────────────────── */

static gboolean reload(gpointer data) {
    sec_t *s = data;

    if (!fxc_alive(s->client)) {
        gtk_label_set_text(GTK_LABEL(s->status),
                           "Not connected to " BRAND_DAEMON
                           ". Sign in from the Appliance page.");
        return G_SOURCE_CONTINUE;
    }

    load_malware(s);
    load_airgap(s);
    load_interfaces(s);

    gtk_label_set_text(GTK_LABEL(s->status),
        "Read from the running daemon over the same API the web console "
        "uses, so the two cannot disagree.");
    return G_SOURCE_CONTINUE;
}

static void on_refresh_clicked(GtkButton *b, gpointer data) {
    (void)b;
    reload(data);
}

static void on_destroy(GtkWidget *w, gpointer data) {
    (void)w;
    sec_t *s = data;
    if (s->timer) g_source_remove(s->timer);
    free(s);
}

GtkWidget *create_security_page(fx_client_t *client) {
    sec_t *s = calloc(1, sizeof(*s));
    s->client = client;

    GtkWidget *scroller = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scroller, TRUE);

    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(page, 16);
    gtk_widget_set_margin_end(page, 16);
    gtk_widget_set_margin_top(page, 14);
    gtk_widget_set_margin_bottom(page, 14);

    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *title = gtk_label_new("Security");
    gtk_widget_add_css_class(title, "page-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_set_hexpand(title, TRUE);
    gtk_box_append(GTK_BOX(head), title);

    GtkWidget *rbtn = gtk_button_new_with_label("Refresh");
    gtk_box_append(GTK_BOX(head), rbtn);
    gtk_box_append(GTK_BOX(page), head);

    s->mw_tiles = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(page), s->mw_tiles);

    s->mw_gaps = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(page), section("Malware coverage", s->mw_gaps));

    s->ag_tiles = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(page), s->ag_tiles);

    s->ag_egress = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(page),
                   section("The appliance's own traffic", s->ag_egress));

    s->ifaces = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(page), section("Interfaces", s->ifaces));

    s->status = gtk_label_new("");
    gtk_widget_add_css_class(s->status, "dash-status");
    gtk_label_set_xalign(GTK_LABEL(s->status), 0.0);
    gtk_label_set_wrap(GTK_LABEL(s->status), TRUE);
    gtk_box_append(GTK_BOX(page), s->status);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), page);

    g_signal_connect(rbtn, "clicked", G_CALLBACK(on_refresh_clicked), s);
    g_signal_connect(page, "destroy", G_CALLBACK(on_destroy), s);

    reload(s);
    s->timer = g_timeout_add_seconds(SEC_REFRESH_SECONDS, reload, s);
    return scroller;
}
