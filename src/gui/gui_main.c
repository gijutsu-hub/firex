#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include "firewall.h"
#include "nfqueue.h"
#include "engine.h"
#include "guiapp.h"
#include "brand.h"

// Global firewall context
firewall_ctx_t *g_fw = NULL;

/*
 * The session this console holds on the local daemon. Once it is
 * connected the daemon owns the packet engine, so the local start/stop
 * controls are disabled rather than offering to run a second one --
 * two engines on one interface is not a state worth being able to reach.
 */
fx_client_t g_client;
gboolean    g_daemon_connected = FALSE;

// Forward declarations
GtkWidget *create_rules_page(firewall_ctx_t *ctx);
GtkWidget *create_monitor_page(firewall_ctx_t *ctx);
GtkWidget *create_stats_page(firewall_ctx_t *ctx);
GtkWidget *create_settings_page(firewall_ctx_t *ctx);
GtkWidget *create_dashboard_page(fx_client_t *client);
GtkWidget *create_security_page(fx_client_t *client);
GtkWidget *gui_login_build(GtkWindow *window, fx_client_t *client,
                           void (*done)(GtkWindow *, fx_client_t *, gpointer),
                           gpointer done_data);
void start_monitor_updates(firewall_ctx_t *ctx);
void start_stats_updates(firewall_ctx_t *ctx);

static GtkWidget *g_sidebar_status = NULL;

/* The stylesheet lives in gui_theme.c. */
void gui_load_css(void);

// ========== HEADER BAR ==========
static GtkWidget *create_header(void) {
    GtkWidget *header = gtk_header_bar_new();
    gtk_widget_add_css_class(header, "header-bar");

    // Logo & Title
    GtkWidget *title_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    GtkWidget *title_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *title = gtk_label_new(BRAND_PRODUCT " by " BRAND_VENDOR);
    gtk_widget_add_css_class(title, "title-text");
    GtkWidget *subtitle = gtk_label_new(BRAND_TAGLINE "  \xc2\xb7  v" BRAND_VERSION);
    gtk_widget_add_css_class(subtitle, "subtitle-text");
    gtk_box_append(GTK_BOX(title_vbox), title);
    gtk_box_append(GTK_BOX(title_vbox), subtitle);

    gtk_box_append(GTK_BOX(title_box), title_vbox);
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), title_box);

    return header;
}

// ========== SIDEBAR NAVIGATION ==========
static void on_sidebar_toggled(GtkToggleButton *btn, gpointer user_data) {
    (void)user_data;
    if (!gtk_toggle_button_get_active(btn)) return;

    GtkWidget *stack = g_object_get_data(G_OBJECT(btn), "stack");
    const char *page = g_object_get_data(G_OBJECT(btn), "page");
    if (stack && page)
        gtk_stack_set_visible_child_name(GTK_STACK(stack), page);
}

// Keep the sidebar badge in step with the engine state, whichever page
// started or stopped it.
static gboolean update_sidebar_status(gpointer data) {
    firewall_ctx_t *ctx = (firewall_ctx_t *)data;
    if (!g_sidebar_status) return G_SOURCE_CONTINUE;

    if (ctx->running) {
        char buf[96];
        const char *eng = ctx->engine == ENGINE_NFQUEUE ? "NFQUEUE"
                        : ctx->engine == ENGINE_XDP     ? "XDP"
                                                        : "Monitor";
        snprintf(buf, sizeof(buf), "\xe2\x97\x8f Running (%s)", eng);
        gtk_label_set_text(GTK_LABEL(g_sidebar_status), buf);
        gtk_widget_remove_css_class(g_sidebar_status, "status-stopped");
        gtk_widget_add_css_class(g_sidebar_status, "status-running");
    } else {
        gtk_label_set_text(GTK_LABEL(g_sidebar_status), "\xe2\x97\x8f Stopped");
        gtk_widget_remove_css_class(g_sidebar_status, "status-running");
        gtk_widget_add_css_class(g_sidebar_status, "status-stopped");
    }
    return G_SOURCE_CONTINUE;
}

// ========== MAIN WINDOW ==========

/*
 * Built once the daemon has handed back a session, and installed into
 * the window the sign-in screen was using. One window for both means the
 * appliance never flashes a desktop between them -- on a kiosk there is
 * nothing behind it to flash.
 */
static void build_console(GtkWindow *window, fx_client_t *client,
                          gpointer user_data) {
    firewall_ctx_t *ctx = (firewall_ctx_t *)user_data;
    g_daemon_connected = client->connected;

    char title[128];
    snprintf(title, sizeof(title), "%s by %s  \xe2\x80\x94  %s (%s)",
             BRAND_PRODUCT, BRAND_VENDOR, client->user, client->role);
    gtk_window_set_title(window, title);

    // Main layout: Sidebar + Content
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    // ===== SIDEBAR =====
    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_add_css_class(sidebar, "sidebar");
    gtk_widget_set_size_request(sidebar, 200, -1);

    GtkWidget *logo_label = gtk_label_new(BRAND_PRODUCT);
    gtk_widget_add_css_class(logo_label, "title-text");
    gtk_widget_set_margin_top(logo_label, 20);
    gtk_widget_set_margin_bottom(logo_label, 30);
    gtk_box_append(GTK_BOX(sidebar), logo_label);

    // Content stack
    GtkWidget *stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);

    // Add pages. The appliance view comes first: it is the one fed by the
    // daemon, so it is the one that agrees with the web console.
    gtk_stack_add_named(GTK_STACK(stack), create_dashboard_page(client), "appliance");
    gtk_stack_add_named(GTK_STACK(stack), create_security_page(client), "security");
    gtk_stack_add_named(GTK_STACK(stack), create_rules_page(ctx), "rules");
    gtk_stack_add_named(GTK_STACK(stack), create_monitor_page(ctx), "monitor");
    gtk_stack_add_named(GTK_STACK(stack), create_stats_page(ctx), "stats");
    gtk_stack_add_named(GTK_STACK(stack), create_settings_page(ctx), "settings");

    // Sidebar buttons
    /*
     * No icons, and no emoji. They are drawn by the operating system, so
     * the same appliance looked different on every workstation and showed
     * a dotted box on the hardened ones with no colour font -- the same
     * rule the web console already followed, which this file did not.
     */
    static const char *pages[]  = {"appliance", "security", "rules", "monitor",
                                   "stats", "settings"};
    static const char *labels[] = {
        "Appliance",
        "Security",
        "Rules",
        "Monitor",
        "Statistics",
        "Settings"
    };

    GtkWidget *first_btn = NULL;
    for (int i = 0; i < (int)(sizeof(pages) / sizeof(pages[0])); i++) {
        GtkWidget *btn = gtk_toggle_button_new_with_label(labels[i]);
        gtk_widget_set_hexpand(btn, TRUE);

        // Group toggle buttons so exactly one page is selected
        if (first_btn) {
            gtk_toggle_button_set_group(GTK_TOGGLE_BUTTON(btn),
                                        GTK_TOGGLE_BUTTON(first_btn));
        } else {
            first_btn = btn;
        }

        g_object_set_data(G_OBJECT(btn), "stack", stack);
        g_object_set_data(G_OBJECT(btn), "page", (gpointer)pages[i]);
        g_signal_connect(btn, "toggled", G_CALLBACK(on_sidebar_toggled), NULL);

        gtk_box_append(GTK_BOX(sidebar), btn);

        if (i == 0) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(btn), TRUE);
    }

    // Status indicator at bottom of sidebar
    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_vexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(sidebar), spacer);

    g_sidebar_status = gtk_label_new("\xe2\x97\x8f Stopped");
    gtk_widget_add_css_class(g_sidebar_status, "status-stopped");
    gtk_widget_set_margin_bottom(g_sidebar_status, 10);
    gtk_box_append(GTK_BOX(sidebar), g_sidebar_status);

    // Pack it all
    gtk_box_append(GTK_BOX(main_box), sidebar);
    gtk_box_append(GTK_BOX(main_box), gtk_separator_new(GTK_ORIENTATION_VERTICAL));

    gtk_widget_set_hexpand(stack, TRUE);
    gtk_widget_set_vexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(main_box), stack);

    gtk_window_set_child(window, main_box);

    // Start periodic updates
    start_monitor_updates(ctx);
    start_stats_updates(ctx);
    g_timeout_add(500, update_sidebar_status, ctx);
}

/* Set by --kiosk / --size / --screenshot on the command line; see main(). */
static gboolean    g_kiosk = FALSE;
static int         g_win_w = 1400, g_win_h = 900;
static const char *g_shot_path = NULL;
static guint       g_shot_delay_ms = 1200;

/*
 * Renders the window to a PNG and exits. The appliance has no desktop
 * and no screenshot tool, so without this there is no way to capture
 * what its own monitor shows -- for documentation, for a support
 * ticket, or to check a change actually looks the way it should.
 */
static gboolean take_screenshot(gpointer data) {
    GtkWidget *window = data;

    int w = gtk_widget_get_width(window);
    int h = gtk_widget_get_height(window);
    if (w <= 0 || h <= 0) { w = g_win_w; h = g_win_h; }

    GskRenderer *renderer = gtk_native_get_renderer(GTK_NATIVE(window));
    if (!renderer) {
        g_printerr("screenshot: the window has no renderer yet\n");
        gtk_window_destroy(GTK_WINDOW(window));
        return G_SOURCE_REMOVE;
    }

    GdkPaintable *paintable = gtk_widget_paintable_new(window);
    GtkSnapshot  *snapshot  = gtk_snapshot_new();
    gdk_paintable_snapshot(paintable, snapshot, w, h);

    GskRenderNode *node = gtk_snapshot_free_to_node(snapshot);
    if (!node) {
        g_printerr("screenshot: nothing was drawn\n");
        g_object_unref(paintable);
        gtk_window_destroy(GTK_WINDOW(window));
        return G_SOURCE_REMOVE;
    }

    graphene_rect_t area = GRAPHENE_RECT_INIT(0, 0, (float)w, (float)h);
    GdkTexture *tex = gsk_renderer_render_texture(renderer, node, &area);

    GError *err = NULL;
    if (tex && gdk_texture_save_to_png(tex, g_shot_path))
        g_print("wrote %s (%dx%d)\n", g_shot_path, w, h);
    else
        g_printerr("screenshot: could not write %s%s%s\n", g_shot_path,
                   err ? ": " : "", err ? err->message : "");
    g_clear_error(&err);

    if (tex) g_object_unref(tex);
    gsk_render_node_unref(node);
    g_object_unref(paintable);

    gtk_window_destroy(GTK_WINDOW(window));
    return G_SOURCE_REMOVE;
}

static void activate(GtkApplication *app, gpointer user_data) {
    gui_load_css();

    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window),
                         BRAND_PRODUCT " by " BRAND_VENDOR);
    gtk_window_set_default_size(GTK_WINDOW(window), g_win_w, g_win_h);
    gtk_window_set_titlebar(GTK_WINDOW(window), create_header());

    /*
     * On the appliance there is no desktop behind this window and no way
     * to resize it, so it is fullscreen and cannot be closed -- closing
     * it would leave a blank monitor with no way back. Everywhere else it
     * is an ordinary resizable window.
     */
    if (g_kiosk) {
        gtk_window_fullscreen(GTK_WINDOW(window));
        gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
        gtk_window_set_deletable(GTK_WINDOW(window), FALSE);
    }

    gtk_window_set_child(GTK_WINDOW(window),
                         gui_login_build(GTK_WINDOW(window), &g_client,
                                         build_console, user_data));
    gtk_window_present(GTK_WINDOW(window));

    /* A beat for the first layout and the first API round trip, so the
     * capture shows the screen rather than an empty frame of it. */
    if (g_shot_path)
        g_timeout_add(g_shot_delay_ms, take_screenshot, window);
}

static void usage(const char *me) {
    printf("%s - %s desktop console\n\n", me, BRAND_FULL);
    printf("Usage: %s [options]\n\n", me);
    printf("  --kiosk            fullscreen, not resizable, cannot be closed\n");
    printf("                     (how the appliance runs it on its own screen)\n");
    printf("  --size WxH         window size when not in kiosk mode\n");
    printf("  --host HOST        the daemon to talk to   (default 127.0.0.1)\n");
    printf("  --port N           its console port        (default 8080)\n");
    printf("  --rules FILE       local rule table for the standalone pages\n");
    printf("  --screenshot FILE  render the screen to a PNG and exit\n");
    printf("  --screenshot-after MS   how long to wait first (default 1200)\n");
    printf("  --help\n\n");
    printf("Sign in with the same account as SSH and the web console.\n");
}

int main(int argc, char *argv[]) {
    const char *host  = "127.0.0.1";
    const char *rules = "config/rules.conf";
    int port = 8080;

    /*
     * Parsed here rather than handed to GTK: g_application_run() treats
     * an option it does not know as a file to open and exits, so the
     * appliance's own --kiosk would stop the console from starting.
     */
    int gtk_argc = 1;
    char *gtk_argv[2] = { argv[0], NULL };

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--kiosk")) {
            g_kiosk = TRUE;
        } else if (!strcmp(argv[i], "--size") && i + 1 < argc) {
            int w = 0, h = 0;
            if (sscanf(argv[++i], "%dx%d", &w, &h) == 2 && w >= 640 && h >= 480) {
                g_win_w = w;
                g_win_h = h;
            } else {
                fprintf(stderr, "%s: --size wants WxH, at least 640x480\n", argv[0]);
                return 2;
            }
        } else if (!strcmp(argv[i], "--host") && i + 1 < argc) {
            host = argv[++i];
        } else if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            port = atoi(argv[++i]);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "%s: --port must be 1-65535\n", argv[0]);
                return 2;
            }
        } else if (!strcmp(argv[i], "--rules") && i + 1 < argc) {
            rules = argv[++i];
        } else if (!strcmp(argv[i], "--screenshot") && i + 1 < argc) {
            g_shot_path = argv[++i];
        } else if (!strcmp(argv[i], "--screenshot-after") && i + 1 < argc) {
            int ms = atoi(argv[++i]);
            if (ms < 100 || ms > 120000) {
                fprintf(stderr, "%s: --screenshot-after wants 100-120000 ms\n",
                        argv[0]);
                return 2;
            }
            g_shot_delay_ms = (guint)ms;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "%s: unknown option '%s'  (try --help)\n",
                    argv[0], argv[i]);
            return 2;
        }
    }

    fxc_init(&g_client, host, port);

    g_fw = fw_create();
    if (!g_fw) {
        fprintf(stderr, "Failed to create firewall context\n");
        return 1;
    }

    // Try to load existing config
    if (fw_load_config(g_fw, rules) != 0)
        fprintf(stderr, "Note: %s not loaded, starting empty\n", rules);

    GtkApplication *app = gtk_application_new(BRAND_APP_ID,
                                              G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), g_fw);

    int status = g_application_run(G_APPLICATION(app), gtk_argc, gtk_argv);

    if (g_client.connected) fxc_logout(&g_client);

    /* Detach XDP / remove iptables rules before tearing the context down;
     * fw_destroy only knows how to stop the raw-socket engine. */
    engine_stop(g_fw);

    g_object_unref(app);
    fw_destroy(g_fw);
    return status;
}
