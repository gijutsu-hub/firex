/*
 * The desktop console's overview page.
 *
 * Everything here comes from the running daemon over the same HTTP API
 * the web console uses. Nothing is computed locally and nothing is
 * cached, so what this screen says and what a browser says are the same
 * sentence from the same source -- which is the whole point of the GUI
 * being a client rather than a second engine.
 */
#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>

#include "guiapp.h"
#include "brand.h"

#define DASH_REFRESH_SECONDS 5

typedef struct {
    fx_client_t *client;

    GtkWidget *banner;        /* default-credential warning, when it applies */
    GtkWidget *tiles;
    GtkWidget *schedules;
    GtkWidget *wan;
    GtkWidget *status;

    guint      timer;
} dash_t;

/* ── small builders ─────────────────────────────────────────────────── */

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

static GtkWidget *num_tile(const char *label, const char *json,
                           const char *key, const char *cls) {
    double d = 0;
    char v[32];
    if (fxj_num(json, key, &d)) snprintf(v, sizeof(v), "%lld", (long long)d);
    else                        snprintf(v, sizeof(v), "\xe2\x80\x94");
    return tile(label, v, cls);
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

/* ── the three live panels ──────────────────────────────────────────── */

static void load_tiles(dash_t *d) {
    clear(d->tiles);

    char err[FXC_ERR_LEN] = "";
    char *vlans = fxc_get(d->client, "/api/vlans", err, sizeof(err));
    if (!vlans) {
        gtk_box_append(GTK_BOX(d->tiles),
                       tile("segmentation", err[0] ? err : "unavailable",
                            "dash-bad"));
        return;
    }

    char n[32];
    snprintf(n, sizeof(n), "%d", fxj_count(vlans, "vlans"));
    gtk_box_append(GTK_BOX(d->tiles), tile("VLANs", n, NULL));

    snprintf(n, sizeof(n), "%d", fxj_count(vlans, "ports"));
    gtk_box_append(GTK_BOX(d->tiles), tile("Ports", n, NULL));

    gtk_box_append(GTK_BOX(d->tiles),
                   num_tile("ACL rules", vlans, "acl_count", NULL));
    gtk_box_append(GTK_BOX(d->tiles),
                   num_tile("Inter-VLAN allowed", vlans, "allowed", "dash-ok"));
    gtk_box_append(GTK_BOX(d->tiles),
                   num_tile("Inter-VLAN denied", vlans, "denied", "dash-warn"));
    gtk_box_append(GTK_BOX(d->tiles),
                   num_tile("Tag violations", vlans, "violations", "dash-bad"));

    free(vlans);
}

/*
 * Schedules are the one piece of policy that changes without anyone
 * touching it, so "which windows are open right now" is worth a panel of
 * its own. `active` is evaluated by the daemon against its own clock --
 * asking the GUI's clock would be a second answer to the same question.
 */
static void load_schedules(dash_t *d) {
    clear(d->schedules);

    char err[FXC_ERR_LEN] = "";
    char *pol = fxc_get(d->client, "/api/policy", err, sizeof(err));
    if (!pol) {
        gtk_box_append(GTK_BOX(d->schedules),
                       cell(err[0] ? err : "unavailable", "dash-bad", -1));
        return;
    }

    GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_append(GTK_BOX(hdr), cell("NAME",   "dash-th", 150));
    gtk_box_append(GTK_BOX(hdr), cell("DAYS",   "dash-th", 150));
    gtk_box_append(GTK_BOX(hdr), cell("WINDOW", "dash-th", 130));
    gtk_box_append(GTK_BOX(hdr), cell("NOW",    "dash-th", 80));
    gtk_box_append(GTK_BOX(d->schedules), hdr);

    int rows = 0;
    for (const char *p = fxj_array(pol, "schedules"); p; p = fxj_next(p)) {
        char name[64] = "", days[64] = "", s[16] = "", e[16] = "";
        double act = 0;

        fxj_str(p, "name", name, sizeof(name));
        fxj_str(p, "days", days, sizeof(days));
        fxj_str(p, "start", s, sizeof(s));
        fxj_str(p, "end", e, sizeof(e));
        fxj_num(p, "active", &act);

        char window[48];
        snprintf(window, sizeof(window), "%s \xe2\x80\x93 %s", s, e);

        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_box_append(GTK_BOX(row), cell(name, "dash-cell-mono", 150));
        gtk_box_append(GTK_BOX(row), cell(days, "dash-cell", 150));
        gtk_box_append(GTK_BOX(row), cell(window, "dash-cell-mono", 130));
        gtk_box_append(GTK_BOX(row), cell(act ? "OPEN" : "closed",
                                          act ? "dash-pill-ok" : "dash-pill-mut",
                                          80));
        gtk_box_append(GTK_BOX(d->schedules), row);
        rows++;
    }

    if (rows == 0)
        gtk_box_append(GTK_BOX(d->schedules),
                       cell("No schedules are defined.", "dash-cell-mut", -1));

    double skipped = 0;
    if (fxj_num(pol, "schedule_skipped", &skipped) && skipped > 0) {
        char t[128];
        snprintf(t, sizeof(t),
                 "%lld rule evaluation(s) skipped because a window was closed.",
                 (long long)skipped);
        gtk_box_append(GTK_BOX(d->schedules), cell(t, "dash-cell-mut", -1));
    }

    /* Aliases and routes live in the same reply; one line is enough. */
    char t[160];
    snprintf(t, sizeof(t), "%d alias(es), %d static route(s) in policy.",
             fxj_count(pol, "aliases"), fxj_count(pol, "routes"));
    gtk_box_append(GTK_BOX(d->schedules), cell(t, "dash-cell-mut", -1));

    free(pol);
}

static void load_wan(dash_t *d) {
    clear(d->wan);

    char err[FXC_ERR_LEN] = "";
    char *wan = fxc_get(d->client, "/api/wan", err, sizeof(err));
    if (!wan) {
        gtk_box_append(GTK_BOX(d->wan),
                       cell(err[0] ? err : "unavailable", "dash-bad", -1));
        return;
    }

    GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_append(GTK_BOX(hdr), cell("LINK",    "dash-th", 110));
    gtk_box_append(GTK_BOX(hdr), cell("GATEWAY", "dash-th", 140));
    gtk_box_append(GTK_BOX(hdr), cell("STATE",   "dash-th", 90));
    gtk_box_append(GTK_BOX(hdr), cell("RTT",     "dash-th", 80));
    gtk_box_append(GTK_BOX(hdr), cell("LOSS",    "dash-th", 70));
    gtk_box_append(GTK_BOX(d->wan), hdr);

    int rows = 0;
    for (const char *p = fxj_array(wan, "links"); p; p = fxj_next(p)) {
        char ifname[32] = "", gw[46] = "", status[24] = "";
        double rtt = 0, loss = 0;

        fxj_str(p, "ifname", ifname, sizeof(ifname));
        fxj_str(p, "gateway", gw, sizeof(gw));
        fxj_str(p, "status", status, sizeof(status));
        fxj_num(p, "rtt_ms", &rtt);
        fxj_num(p, "loss_pct", &loss);

        char rtts[24], losss[24];
        snprintf(rtts, sizeof(rtts), "%.1f ms", rtt);
        snprintf(losss, sizeof(losss), "%.0f%%", loss);

        const char *pill = !strcmp(status, "up")   ? "dash-pill-ok"
                         : !strcmp(status, "down") ? "dash-pill-bad"
                                                   : "dash-pill-mut";

        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_box_append(GTK_BOX(row), cell(ifname, "dash-cell-mono", 110));
        gtk_box_append(GTK_BOX(row), cell(gw, "dash-cell-mono", 140));
        gtk_box_append(GTK_BOX(row), cell(status, pill, 90));
        gtk_box_append(GTK_BOX(row), cell(rtts, "dash-cell-mono", 80));
        gtk_box_append(GTK_BOX(row), cell(losss, "dash-cell-mono", 70));
        gtk_box_append(GTK_BOX(d->wan), row);
        rows++;
    }

    if (rows == 0)
        gtk_box_append(GTK_BOX(d->wan),
                       cell("No WAN links are configured.", "dash-cell-mut", -1));
    free(wan);
}

/*
 * The same warning the web console and the serial menu carry. Three
 * surfaces saying it and a fourth staying quiet is how a shipped password
 * survives to production.
 */
static void load_banner(dash_t *d) {
    gtk_widget_set_visible(d->banner, FALSE);

    char err[FXC_ERR_LEN] = "";
    char *acc = fxc_get(d->client, "/api/accounts", err, sizeof(err));
    if (!acc) return;

    double n = 0;
    if (fxj_num(acc, "defaults", &n) && n > 0) {
        char t[256];
        snprintf(t, sizeof(t),
                 "%lld account%s still on the shipped password. "
                 "Anyone who can reach port 22 or %d knows it. "
                 "Change it under System in the web console.",
                 (long long)n, n == 1 ? " is" : "s are", d->client->port);
        gtk_label_set_text(GTK_LABEL(d->banner), t);
        gtk_widget_set_visible(d->banner, TRUE);
    }
    free(acc);
}

static gboolean reload(gpointer data) {
    dash_t *d = data;

    if (!d->client->connected) {
        gtk_label_set_text(GTK_LABEL(d->status),
                           "Session ended. Restart the console to sign in again.");
        return G_SOURCE_CONTINUE;
    }

    load_banner(d);
    load_tiles(d);
    load_schedules(d);
    load_wan(d);

    char t[320];
    char ip[64];
    fx_primary_address(ip, sizeof(ip));
    snprintf(t, sizeof(t),
             "Signed in as %s (%s) \xc2\xb7 live from %s on %s:%d \xc2\xb7 "
             "web console http://%s:%d/ui",
             d->client->user, d->client->role, BRAND_DAEMON,
             d->client->host, d->client->port, ip, d->client->port);
    gtk_label_set_text(GTK_LABEL(d->status), t);
    return G_SOURCE_CONTINUE;
}

static void on_destroy(GtkWidget *w, gpointer data) {
    (void)w;
    dash_t *d = data;
    if (d->timer) g_source_remove(d->timer);
    g_free(d);
}

static void on_refresh_clicked(GtkButton *b, gpointer data) {
    (void)b;
    reload(data);
}

GtkWidget *create_dashboard_page(fx_client_t *client) {
    dash_t *d = g_new0(dash_t, 1);
    d->client = client;

    GtkWidget *scroller = gtk_scrolled_window_new();
    gtk_widget_set_hexpand(scroller, TRUE);
    gtk_widget_set_vexpand(scroller, TRUE);

    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_add_css_class(page, "dash-page");

    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *title = gtk_label_new("Appliance");
    gtk_widget_add_css_class(title, "dash-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_set_hexpand(title, TRUE);
    GtkWidget *rbtn = gtk_button_new_with_label("Refresh");
    gtk_widget_add_css_class(rbtn, "dash-refresh");
    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(head), rbtn);
    gtk_box_append(GTK_BOX(page), head);

    d->banner = gtk_label_new("");
    gtk_widget_add_css_class(d->banner, "dash-banner");
    gtk_label_set_xalign(GTK_LABEL(d->banner), 0.0);
    gtk_label_set_wrap(GTK_LABEL(d->banner), TRUE);
    gtk_widget_set_visible(d->banner, FALSE);
    gtk_box_append(GTK_BOX(page), d->banner);

    d->tiles = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(page), d->tiles);

    d->schedules = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(page), section("Schedules", d->schedules));

    d->wan = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_append(GTK_BOX(page), section("WAN links", d->wan));

    d->status = gtk_label_new("");
    gtk_widget_add_css_class(d->status, "dash-status");
    gtk_label_set_xalign(GTK_LABEL(d->status), 0.0);
    gtk_label_set_wrap(GTK_LABEL(d->status), TRUE);
    gtk_box_append(GTK_BOX(page), d->status);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), page);

    g_signal_connect(rbtn, "clicked", G_CALLBACK(on_refresh_clicked), d);
    g_signal_connect(page, "destroy", G_CALLBACK(on_destroy), d);

    reload(d);
    d->timer = g_timeout_add_seconds(DASH_REFRESH_SECONDS, reload, d);
    return scroller;
}
