#include <gtk/gtk.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include "firewall.h"
#include "nfqueue.h"
#include "xdp_filter.h"
#include "engine.h"
#include "logger.h"

extern firewall_ctx_t *g_fw;

static GtkWidget *iface_entry;
static GtkWidget *engine_dropdown;
static GtkWidget *policy_dropdown;
static GtkWidget *queue_spin;
static GtkWidget *logfile_switch;
static GtkWidget *status_label_settings;
static GtkWidget *start_stop_btn;

static void alert(GtkWidget *parent, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
static void alert(GtkWidget *parent, const char *fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    GtkAlertDialog *dlg = gtk_alert_dialog_new("%s", msg);
    gtk_alert_dialog_show(dlg, GTK_WINDOW(gtk_widget_get_root(parent)));
    g_object_unref(dlg);
}

// First non-loopback interface, so the field starts on something real.
static void guess_interface(char *out, size_t len) {
    struct if_nameindex *list = if_nameindex();
    snprintf(out, len, "eth0");
    if (!list) return;

    for (struct if_nameindex *p = list; p->if_index != 0; p++) {
        if (strcmp(p->if_name, "lo") != 0) {
            snprintf(out, len, "%s", p->if_name);
            break;
        }
    }
    if_freenameindex(list);
}

static void set_running_ui(bool running, const char *detail) {
    if (running) {
        gtk_button_set_label(GTK_BUTTON(start_stop_btn), "Stop Firewall");
        gtk_widget_remove_css_class(start_stop_btn, "start-btn");
        gtk_widget_add_css_class(start_stop_btn, "stop-btn");
        gtk_label_set_text(GTK_LABEL(status_label_settings), detail);
        gtk_widget_remove_css_class(status_label_settings, "status-stopped");
        gtk_widget_add_css_class(status_label_settings, "status-running");
    } else {
        gtk_button_set_label(GTK_BUTTON(start_stop_btn), "Start Firewall");
        gtk_widget_remove_css_class(start_stop_btn, "stop-btn");
        gtk_widget_add_css_class(start_stop_btn, "start-btn");
        gtk_label_set_text(GTK_LABEL(status_label_settings), detail);
        gtk_widget_remove_css_class(status_label_settings, "status-running");
        gtk_widget_add_css_class(status_label_settings, "status-stopped");
    }
    gtk_widget_set_sensitive(iface_entry, !running);
    gtk_widget_set_sensitive(engine_dropdown, !running);
    gtk_widget_set_sensitive(queue_spin, !running);
}

extern gboolean g_daemon_connected;

static void on_start_stop(GtkButton *btn, gpointer data) {
    (void)data;
    GtkWidget *w = GTK_WIDGET(btn);

    /*
     * On the appliance the daemon owns the interface. Starting a second
     * engine here would attach another XDP program or insert another
     * NFQUEUE rule on the same link, and the two would then disagree
     * about what is being dropped.
     */
    if (g_daemon_connected) {
        alert(w, "The appliance daemon owns the packet engine.\n\n"
                 "Change the engine under Settings in the web console, or "
                 "with firexd on the command line. Starting a second engine "
                 "on the same interface would leave two of them deciding "
                 "about the same packets.");
        return;
    }

    if (g_fw->running) {
        // STOP
        engine_stop(g_fw);
        logger_close(g_fw);
        set_running_ui(false, "\xe2\x97\x8f Stopped");
        return;
    }

    // START
    const char *iface = gtk_editable_get_text(GTK_EDITABLE(iface_entry));
    if (!iface || !iface[0]) {
        alert(w, "Enter a network interface first.");
        return;
    }

    int engine_idx = (int)gtk_drop_down_get_selected(GTK_DROP_DOWN(engine_dropdown));

    if (engine_idx == 2 && !xdp_engine_available()) {
        alert(w, "The XDP program has not been compiled.\n\n"
                 "Build it with:  make xdp\n"
                 "(needs clang and libbpf-dev)");
        return;
    }

    if (geteuid() != 0) {
        alert(w, "Packet capture needs root privileges.\n\n"
                 "Quit and start FlameWall with: sudo ./flamewall");
        return;
    }

    int policy_idx = (int)gtk_drop_down_get_selected(GTK_DROP_DOWN(policy_dropdown));
    g_fw->default_policy = (policy_idx == 0) ? ACTION_ALLOW : ACTION_BLOCK;
    g_fw->queue_num = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(queue_spin));

    if (gtk_switch_get_active(GTK_SWITCH(logfile_switch))) {
        const char *path = g_fw->log_file[0] ? g_fw->log_file : "flamewall.log";
        if (logger_init(g_fw, path) != 0)
            alert(w, "Could not open the log file %s - continuing without it.", path);
    }

    fw_reset_stats(g_fw);

    engine_t engine = engine_idx == 1 ? ENGINE_NFQUEUE
                    : engine_idx == 2 ? ENGINE_XDP
                                      : ENGINE_RAW_SOCKET;

    if (engine_start(g_fw, iface, engine) != 0) {
        logger_close(g_fw);
        const char *detail = engine_detail(engine);
        if (detail)
            alert(w, "%s", detail);
        else
            alert(w, "Failed to start on \"%s\".\n\n"
                     "Check that the interface exists and, for NFQUEUE, that "
                     "iptables and libnetfilter_queue are usable. The terminal "
                     "output has the specific error.", iface);
        set_running_ui(false, "\xe2\x97\x8f Stopped");
        return;
    }

    char status[128];
    snprintf(status, sizeof(status), "\xe2\x97\x8f Running on %s (%s)",
             iface, engine_name(engine));
    set_running_ui(true, status);

    /* XDP cannot carry every rule into the kernel; say so rather than let
     * the user assume the DPI rules are being enforced. */
    const char *detail = engine_detail(engine);
    if (detail)
        alert(w, "%s", detail);
}

GtkWidget *create_settings_page(firewall_ctx_t *ctx) {
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);
    gtk_widget_set_margin_top(page, 20);
    gtk_widget_set_margin_bottom(page, 20);

    GtkWidget *title = gtk_label_new("Settings");
    gtk_widget_add_css_class(title, "title-text");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(page), title);

    // Settings card
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_widget_add_css_class(card, "card");

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 15);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 15);
    int row = 0;

    // Interface
    GtkWidget *l1 = gtk_label_new("Network Interface:");
    gtk_widget_set_halign(l1, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), l1, 0, row, 1, 1);
    iface_entry = gtk_entry_new();
    if (ctx->interface[0]) {
        gtk_editable_set_text(GTK_EDITABLE(iface_entry), ctx->interface);
    } else {
        char guess[MAX_IFACE_NAME];
        guess_interface(guess, sizeof(guess));
        gtk_editable_set_text(GTK_EDITABLE(iface_entry), guess);
    }
    gtk_widget_set_hexpand(iface_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), iface_entry, 1, row++, 1, 1);

    // Engine
    static const char *engines[] = {
        "Raw Socket (Monitor Only)",
        "NFQUEUE (Block Packets)",
        "XDP/eBPF (kernel offload, inbound only)",
        NULL
    };
    GtkWidget *l2 = gtk_label_new("Engine:");
    gtk_widget_set_halign(l2, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), l2, 0, row, 1, 1);
    engine_dropdown = gtk_drop_down_new_from_strings(engines);
    gtk_drop_down_set_selected(GTK_DROP_DOWN(engine_dropdown),
                               ctx->engine <= ENGINE_XDP ? ctx->engine : 0);
    gtk_grid_attach(GTK_GRID(grid), engine_dropdown, 1, row++, 1, 1);

    // Default Policy
    static const char *policies[] = {"ALLOW (blacklist mode)", "BLOCK (whitelist mode)", NULL};
    GtkWidget *l3 = gtk_label_new("Default Policy:");
    gtk_widget_set_halign(l3, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), l3, 0, row, 1, 1);
    policy_dropdown = gtk_drop_down_new_from_strings(policies);
    gtk_drop_down_set_selected(GTK_DROP_DOWN(policy_dropdown),
                               ctx->default_policy == ACTION_BLOCK ? 1 : 0);
    gtk_grid_attach(GTK_GRID(grid), policy_dropdown, 1, row++, 1, 1);

    // NFQUEUE queue number
    GtkWidget *l4 = gtk_label_new("NFQUEUE Number:");
    gtk_widget_set_halign(l4, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), l4, 0, row, 1, 1);
    queue_spin = gtk_spin_button_new_with_range(0, 65535, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(queue_spin), ctx->queue_num);
    gtk_grid_attach(GTK_GRID(grid), queue_spin, 1, row++, 1, 1);

    // Log to file
    GtkWidget *l5 = gtk_label_new("Log to file:");
    gtk_widget_set_halign(l5, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), l5, 0, row, 1, 1);
    logfile_switch = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(logfile_switch), ctx->log_to_file);
    gtk_widget_set_halign(logfile_switch, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), logfile_switch, 1, row++, 1, 1);

    gtk_box_append(GTK_BOX(card), grid);

    // Status
    status_label_settings = gtk_label_new("\xe2\x97\x8f Stopped");
    gtk_widget_add_css_class(status_label_settings, "status-stopped");
    gtk_widget_set_halign(status_label_settings, GTK_ALIGN_START);
    gtk_widget_set_margin_top(status_label_settings, 10);
    gtk_box_append(GTK_BOX(card), status_label_settings);

    // Start/Stop button
    start_stop_btn = gtk_button_new_with_label("Start Firewall");
    gtk_widget_add_css_class(start_stop_btn, "start-btn");
    if (g_daemon_connected) {
        gtk_button_set_label(GTK_BUTTON(start_stop_btn),
                             "Managed by the daemon");
        gtk_widget_set_tooltip_text(start_stop_btn,
            "firexd owns the packet engine on this appliance.");
    }
    gtk_widget_set_size_request(start_stop_btn, 200, 50);
    g_signal_connect(start_stop_btn, "clicked", G_CALLBACK(on_start_stop), NULL);
    gtk_widget_set_halign(start_stop_btn, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(start_stop_btn, 15);
    gtk_box_append(GTK_BOX(card), start_stop_btn);

    gtk_box_append(GTK_BOX(page), card);

    // Info card
    GtkWidget *info_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(info_card, "card");

    GtkWidget *info_title = gtk_label_new("Engine Information");
    gtk_widget_set_halign(info_title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(info_card), info_title);

    static const char *info_text =
        "\xe2\x96\xaa <b>Raw Socket</b>: Monitor-only mode. Sees every frame on the "
        "interface but cannot block anything. Best for learning and analysis.\n\n"
        "\xe2\x96\xaa <b>NFQUEUE</b>: Full firewall mode. Really drops and accepts "
        "packets via iptables + netfilter_queue. Starting it inserts NFQUEUE rules "
        "into the INPUT, OUTPUT and FORWARD chains; stopping removes them again.\n\n"
        "\xe2\x96\xaa <b>XDP/eBPF</b>: Kernel-level filtering. Drops packets in the "
        "driver, before the network stack allocates an skb, so it is by far the "
        "fastest option. Two limits: it runs on <b>ingress only</b>, so outbound "
        "traffic is untouched, and DPI rules cannot be offloaded because BPF has "
        "no regex engine - the Start dialog lists any rule left behind.\n\n"
        "All three engines need root. Run with <tt>sudo ./flamewall</tt>.";

    GtkWidget *info_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(info_label), info_text);
    gtk_label_set_wrap(GTK_LABEL(info_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(info_label), 0.0);
    gtk_widget_set_halign(info_label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(info_card), info_label);

    gtk_box_append(GTK_BOX(page), info_card);

    return page;
}
