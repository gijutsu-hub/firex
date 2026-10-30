/*
 * The desktop console's sign-in screen.
 *
 * This is the first thing the appliance shows on its own monitor, and it
 * has two jobs. The obvious one is authentication, against the daemon and
 * therefore against the same accounts as SSH, the serial menu and the web
 * console. The less obvious one matters more in practice: it tells you
 * where the appliance IS. Somebody standing in front of a firewall that
 * will not let them in needs its address before anything else, and
 * "run ifconfig" is not advice you can take from a login prompt.
 */
#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <string.h>

#include "guiapp.h"
#include "brand.h"

/*
 * Where the mark is looked for, in order. The appliance path comes
 * first, because on the appliance that is the only one that should ever
 * win. The rest are for running the console straight out of a build
 * tree, which is how it gets looked at during development -- without
 * them the sign-in screen comes up with an empty space where the logo
 * belongs and nothing to say why.
 */
static const char *const LOGO_PATHS[] = {
    "/usr/local/share/firex/logo.png",
    "board/splash/logo.png",
    "../board/splash/logo.png",
    NULL
};

static const char *logo_file(void) {
    const char *env = g_getenv("FIREX_LOGO");
    if (env && *env && g_file_test(env, G_FILE_TEST_EXISTS)) return env;
    for (int i = 0; LOGO_PATHS[i]; i++)
        if (g_file_test(LOGO_PATHS[i], G_FILE_TEST_EXISTS)) return LOGO_PATHS[i];
    return NULL;
}

typedef struct {
    fx_client_t  *client;
    GtkWindow    *window;
    GtkWidget    *user;
    GtkWidget    *pass;
    GtkWidget    *button;
    GtkWidget    *message;
    GtkWidget    *netbox;
    guint         refresh;

    void        (*done)(GtkWindow *, fx_client_t *, gpointer);
    gpointer      done_data;
} login_t;

static void say(login_t *l, const char *text, bool bad) {
    gtk_label_set_text(GTK_LABEL(l->message), text ? text : "");
    if (bad) {
        gtk_widget_remove_css_class(l->message, "login-note");
        gtk_widget_add_css_class(l->message, "login-error");
    } else {
        gtk_widget_remove_css_class(l->message, "login-error");
        gtk_widget_add_css_class(l->message, "login-note");
    }
}

/* ── where am I ─────────────────────────────────────────────────────── */

static GtkWidget *kv_row(const char *k, const char *v, const char *vclass) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    GtkWidget *kl = gtk_label_new(k);
    gtk_widget_add_css_class(kl, "net-key");
    gtk_label_set_xalign(GTK_LABEL(kl), 0.0);
    gtk_widget_set_size_request(kl, 90, -1);

    GtkWidget *vl = gtk_label_new(v);
    gtk_widget_add_css_class(vl, vclass ? vclass : "net-val");
    gtk_label_set_xalign(GTK_LABEL(vl), 0.0);
    gtk_label_set_selectable(GTK_LABEL(vl), TRUE);
    gtk_widget_set_hexpand(vl, TRUE);

    gtk_box_append(GTK_BOX(row), kl);
    gtk_box_append(GTK_BOX(row), vl);
    return row;
}

static void fill_network(login_t *l) {
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(l->netbox)))
        gtk_box_remove(GTK_BOX(l->netbox), child);

    fx_ifinfo_t ifs[FX_IFINFO_MAX];
    int n = fx_ifinfo(ifs, FX_IFINFO_MAX);

    GtkWidget *head = gtk_label_new("INTERFACES");
    gtk_widget_add_css_class(head, "net-head");
    gtk_label_set_xalign(GTK_LABEL(head), 0.0);
    gtk_box_append(GTK_BOX(l->netbox), head);

    int shown = 0;
    for (int i = 0; i < n; i++) {
        if (ifs[i].loopback) continue;       /* 127.0.0.1 helps nobody here */

        char v[128];
        const char *cls = "net-val";
        if (ifs[i].addr[0]) {
            snprintf(v, sizeof(v), "%s%s", ifs[i].addr,
                     ifs[i].up ? "" : "   (link down)");
            cls = ifs[i].up ? "net-val-ok" : "net-val-warn";
        } else {
            snprintf(v, sizeof(v), "%s", ifs[i].up ? "up, no address"
                                                   : "down, no address");
            cls = "net-val-warn";
        }
        gtk_box_append(GTK_BOX(l->netbox), kv_row(ifs[i].name, v, cls));
        shown++;
    }

    if (shown == 0)
        gtk_box_append(GTK_BOX(l->netbox),
                       kv_row("none", "no network interfaces are configured",
                              "net-val-warn"));

    /* The two addresses somebody actually needs to type. */
    char ip[64];
    fx_primary_address(ip, sizeof(ip));

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_margin_top(sep, 10);
    gtk_widget_set_margin_bottom(sep, 10);
    gtk_box_append(GTK_BOX(l->netbox), sep);

    GtkWidget *reach = gtk_label_new("REACH IT FROM ANOTHER MACHINE");
    gtk_widget_add_css_class(reach, "net-head");
    gtk_label_set_xalign(GTK_LABEL(reach), 0.0);
    gtk_box_append(GTK_BOX(l->netbox), reach);

    char url[160], ssh[160];
    snprintf(url, sizeof(url), "http://%s:%d/ui", ip, l->client->port);
    snprintf(ssh, sizeof(ssh), "ssh admin@%s", ip);
    gtk_box_append(GTK_BOX(l->netbox), kv_row("Web", url, "net-val-ok"));
    gtk_box_append(GTK_BOX(l->netbox), kv_row("SSH", ssh, "net-val-ok"));

    /* Whether the thing behind all of this is actually up. */
    bool alive = fxc_alive(l->client);
    gtk_box_append(GTK_BOX(l->netbox),
        kv_row("Daemon", alive ? BRAND_DAEMON " is running"
                               : BRAND_DAEMON " is NOT running",
               alive ? "net-val-ok" : "net-val-bad"));
}

static gboolean refresh_network(gpointer data) {
    fill_network((login_t *)data);
    return G_SOURCE_CONTINUE;
}

/* ── signing in ─────────────────────────────────────────────────────── */

static void busy(login_t *l, gboolean on) {
    gtk_widget_set_sensitive(l->button, !on);
    gtk_widget_set_sensitive(l->user, !on);
    gtk_widget_set_sensitive(l->pass, !on);
}

static void attempt(login_t *l) {
    const char *user = gtk_editable_get_text(GTK_EDITABLE(l->user));
    const char *pass = gtk_editable_get_text(GTK_EDITABLE(l->pass));

    if (!user || !*user) { say(l, "Enter a user name.", true); return; }

    busy(l, TRUE);
    say(l, "Signing in\xe2\x80\xa6", false);

    char err[FXC_ERR_LEN] = "";
    int rc = fxc_login(l->client, user, pass ? pass : "", err, sizeof(err));

    /* Cleared whichever way it went: a failed attempt leaving the password
     * on screen is how the next person reads it. */
    gtk_editable_set_text(GTK_EDITABLE(l->pass), "");

    if (rc != 0) {
        busy(l, FALSE);
        say(l, err[0] ? err : "Sign-in failed.", true);
        gtk_widget_grab_focus(l->pass);
        return;
    }

    if (l->refresh) { g_source_remove(l->refresh); l->refresh = 0; }
    if (l->done) l->done(l->window, l->client, l->done_data);
}

static void on_login_clicked(GtkButton *b, gpointer data) {
    (void)b;
    attempt((login_t *)data);
}

static void on_entry_activate(GtkEntry *e, gpointer data) {
    login_t *l = data;
    /* Enter in the user field moves on rather than submitting a blank
     * password, which is the usual way this gets annoying. */
    if (GTK_WIDGET(e) == l->user && !*gtk_editable_get_text(GTK_EDITABLE(l->pass))) {
        gtk_widget_grab_focus(l->pass);
        return;
    }
    attempt(l);
}

static void on_destroy(GtkWidget *w, gpointer data) {
    (void)w;
    login_t *l = data;
    if (l->refresh) g_source_remove(l->refresh);
    g_free(l);
}

/* ── the screen ─────────────────────────────────────────────────────── */

GtkWidget *gui_login_build(GtkWindow *window, fx_client_t *client,
                           void (*done)(GtkWindow *, fx_client_t *, gpointer),
                           gpointer done_data) {
    login_t *l = g_new0(login_t, 1);
    l->client    = client;
    l->window    = window;
    l->done      = done;
    l->done_data = done_data;

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_add_css_class(root, "login-root");

    /*
     * ---- left: who this is ----
     *
     * Two boxes, not one: the outer panel fills the height so its
     * background reaches the top and bottom edges, while the inner box
     * centres the content within it. Centring the panel itself leaves
     * the colour floating in a band down the middle of the screen.
     */
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(left, "login-left");
    gtk_widget_set_size_request(left, 440, -1);
    gtk_widget_set_valign(left, GTK_ALIGN_FILL);

    GtkWidget *left_inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_valign(left_inner, GTK_ALIGN_CENTER);
    gtk_widget_set_vexpand(left_inner, TRUE);
    gtk_box_append(GTK_BOX(left), left_inner);

    const char *logo_path = logo_file();
    if (logo_path) {
        GtkWidget *logo = gtk_picture_new_for_filename(logo_path);
        gtk_widget_set_size_request(logo, 132, 132);
        gtk_widget_set_halign(logo, GTK_ALIGN_CENTER);
        gtk_picture_set_can_shrink(GTK_PICTURE(logo), TRUE);
        gtk_widget_set_margin_bottom(logo, 22);
        gtk_box_append(GTK_BOX(left_inner), logo);
    }

    GtkWidget *name = gtk_label_new(BRAND_PRODUCT " by " BRAND_VENDOR);
    gtk_widget_add_css_class(name, "login-brand");
    gtk_box_append(GTK_BOX(left_inner), name);

    GtkWidget *tag = gtk_label_new(BRAND_TAGLINE);
    gtk_widget_add_css_class(tag, "login-tagline");
    gtk_widget_set_margin_bottom(tag, 28);
    gtk_box_append(GTK_BOX(left_inner), tag);

    l->netbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_add_css_class(l->netbox, "login-net");
    gtk_box_append(GTK_BOX(left_inner), l->netbox);
    fill_network(l);
    /* Addresses arrive from DHCP after this screen is already up. */
    l->refresh = g_timeout_add_seconds(5, refresh_network, l);

    GtkWidget *ver = gtk_label_new(BRAND_PRODUCT " " BRAND_VERSION
                                   "   " BRAND_EDITION);
    gtk_widget_add_css_class(ver, "login-version");
    gtk_widget_set_margin_top(ver, 24);
    gtk_box_append(GTK_BOX(left_inner), ver);

    /* ---- right: the form ---- */
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_hexpand(right, TRUE);
    gtk_widget_set_valign(right, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(right, GTK_ALIGN_CENTER);

    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(card, "login-card");
    gtk_widget_set_size_request(card, 380, -1);

    GtkWidget *title = gtk_label_new("Sign in");
    gtk_widget_add_css_class(title, "login-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_box_append(GTK_BOX(card), title);

    GtkWidget *sub = gtk_label_new("This console manages live network segmentation.");
    gtk_widget_add_css_class(sub, "login-sub");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0);
    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_widget_set_margin_bottom(sub, 22);
    gtk_box_append(GTK_BOX(card), sub);

    GtkWidget *ulab = gtk_label_new("User");
    gtk_widget_add_css_class(ulab, "login-label");
    gtk_label_set_xalign(GTK_LABEL(ulab), 0.0);
    gtk_box_append(GTK_BOX(card), ulab);

    l->user = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(l->user), "admin");
    gtk_widget_set_margin_bottom(l->user, 14);
    gtk_box_append(GTK_BOX(card), l->user);

    GtkWidget *plab = gtk_label_new("Password");
    gtk_widget_add_css_class(plab, "login-label");
    gtk_label_set_xalign(GTK_LABEL(plab), 0.0);
    gtk_box_append(GTK_BOX(card), plab);

    l->pass = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(l->pass), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(l->pass), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_widget_set_margin_bottom(l->pass, 20);
    gtk_box_append(GTK_BOX(card), l->pass);

    l->button = gtk_button_new_with_label("Sign in");
    gtk_widget_add_css_class(l->button, "login-button");
    gtk_box_append(GTK_BOX(card), l->button);

    l->message = gtk_label_new("");
    gtk_widget_add_css_class(l->message, "login-note");
    gtk_label_set_xalign(GTK_LABEL(l->message), 0.0);
    gtk_label_set_wrap(GTK_LABEL(l->message), TRUE);
    gtk_widget_set_margin_top(l->message, 16);
    gtk_widget_set_size_request(l->message, 340, -1);
    gtk_box_append(GTK_BOX(card), l->message);

    gtk_box_append(GTK_BOX(right), card);

    GtkWidget *by = gtk_label_new(BRAND_AUTHOR);
    gtk_widget_add_css_class(by, "login-by");
    gtk_widget_set_margin_top(by, 30);
    gtk_box_append(GTK_BOX(right), by);

    gtk_box_append(GTK_BOX(root), left);
    gtk_box_append(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_VERTICAL));
    gtk_box_append(GTK_BOX(root), right);

    g_signal_connect(l->button, "clicked", G_CALLBACK(on_login_clicked), l);
    g_signal_connect(l->user, "activate", G_CALLBACK(on_entry_activate), l);
    g_signal_connect(l->pass, "activate", G_CALLBACK(on_entry_activate), l);
    g_signal_connect(root, "destroy", G_CALLBACK(on_destroy), l);

    gtk_widget_grab_focus(l->user);
    return root;
}
