#include <gtk/gtk.h>
#include <stdio.h>
#include "firewall.h"

extern firewall_ctx_t *g_fw;

static GtkWidget *total_label, *allowed_label, *blocked_label;
static GtkWidget *tcp_label, *udp_label, *icmp_label, *arp_label;
static GtkWidget *pps_label, *bps_label;
static GtkWidget *uptime_label;
static GtkWidget *chart_area;

// Simple bar chart drawing
static void draw_chart(GtkDrawingArea *area, cairo_t *cr,
                       int width, int height, gpointer data) {
    (void)area; (void)data;
    fw_stats_t stats = fw_get_stats(g_fw);

    // Background
    cairo_set_source_rgb(cr, 0.05, 0.07, 0.09);
    cairo_rectangle(cr, 0, 0, width, height);
    cairo_fill(cr);

    unsigned long values[] = {
        stats.tcp_count, stats.udp_count,
        stats.icmp_count, stats.arp_count, stats.other_count
    };
    static const char *labels[] = {"TCP", "UDP", "ICMP", "ARP", "Other"};
    static const double colors[][3] = {
        {0.0, 1.0, 0.53},   // Green
        {0.0, 0.6, 1.0},    // Blue
        {0.91, 0.27, 0.37}, // Red
        {1.0, 0.8, 0.0},    // Yellow
        {0.6, 0.4, 0.8}     // Purple
    };

    unsigned long max_val = 1;
    for (int i = 0; i < 5; i++)
        if (values[i] > max_val) max_val = values[i];

    int margin = 30;
    int bar_width = (width - 2 * margin) / 5;
    if (bar_width < 10) bar_width = 10;

    for (int i = 0; i < 5; i++) {
        double bar_height = ((double)values[i] / max_val) * (height - 80);
        if (bar_height < 0) bar_height = 0;
        int x = margin + i * bar_width;
        int y = height - 40 - (int)bar_height;

        cairo_set_source_rgb(cr, colors[i][0], colors[i][1], colors[i][2]);
        cairo_rectangle(cr, x, y, bar_width - 8, bar_height);
        cairo_fill(cr);

        // Label
        cairo_set_source_rgb(cr, 0.8, 0.8, 0.9);
        cairo_select_font_face(cr, "monospace", CAIRO_FONT_SLANT_NORMAL,
                               CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 11);
        cairo_move_to(cr, x + 4, height - 20);
        cairo_show_text(cr, labels[i]);

        // Value
        char val[32];
        snprintf(val, sizeof(val), "%lu", values[i]);
        cairo_move_to(cr, x + 4, y - 5);
        cairo_show_text(cr, val);
    }

    // Title
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_set_font_size(cr, 14);
    cairo_move_to(cr, margin, 20);
    cairo_show_text(cr, "Protocol Distribution");
}

static GtkWidget *create_stat_card(const char *label, GtkWidget **value_label) {
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_add_css_class(card, "stat-card");
    gtk_widget_set_hexpand(card, TRUE);

    *value_label = gtk_label_new("0");
    gtk_widget_add_css_class(*value_label, "stat-number");
    gtk_box_append(GTK_BOX(card), *value_label);

    GtkWidget *lbl = gtk_label_new(label);
    gtk_widget_add_css_class(lbl, "stat-label");
    gtk_box_append(GTK_BOX(card), lbl);

    return card;
}

static gboolean update_stats_ui(gpointer data) {
    (void)data;
    fw_stats_t stats = fw_get_stats(g_fw);

    char buf[64];

    snprintf(buf, sizeof(buf), "%lu", stats.total_packets);
    gtk_label_set_text(GTK_LABEL(total_label), buf);

    snprintf(buf, sizeof(buf), "%lu", stats.allowed);
    gtk_label_set_text(GTK_LABEL(allowed_label), buf);

    snprintf(buf, sizeof(buf), "%lu", stats.blocked);
    gtk_label_set_text(GTK_LABEL(blocked_label), buf);

    snprintf(buf, sizeof(buf), "%lu", stats.tcp_count);
    gtk_label_set_text(GTK_LABEL(tcp_label), buf);

    snprintf(buf, sizeof(buf), "%lu", stats.udp_count);
    gtk_label_set_text(GTK_LABEL(udp_label), buf);

    snprintf(buf, sizeof(buf), "%lu", stats.icmp_count);
    gtk_label_set_text(GTK_LABEL(icmp_label), buf);

    snprintf(buf, sizeof(buf), "%lu", stats.arp_count);
    gtk_label_set_text(GTK_LABEL(arp_label), buf);

    snprintf(buf, sizeof(buf), "%.1f pkt/s", stats.packets_per_second);
    gtk_label_set_text(GTK_LABEL(pps_label), buf);

    snprintf(buf, sizeof(buf), "%.1f KB/s", stats.bytes_per_second / 1024.0);
    gtk_label_set_text(GTK_LABEL(bps_label), buf);

    long uptime = (long)(time(NULL) - stats.start_time);
    if (uptime < 0) uptime = 0;
    snprintf(buf, sizeof(buf), "%02ld:%02ld:%02ld",
             uptime / 3600, (uptime % 3600) / 60, uptime % 60);
    gtk_label_set_text(GTK_LABEL(uptime_label), buf);

    // Redraw chart
    if (chart_area) gtk_widget_queue_draw(chart_area);

    return G_SOURCE_CONTINUE;
}

void start_stats_updates(firewall_ctx_t *ctx) {
    (void)ctx;
    g_timeout_add(1000, update_stats_ui, NULL);
}

static void on_reset_stats(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    fw_reset_stats(g_fw);
}

GtkWidget *create_stats_page(firewall_ctx_t *ctx) {
    (void)ctx;
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);
    gtk_widget_set_margin_top(page, 20);
    gtk_widget_set_margin_bottom(page, 20);

    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *title = gtk_label_new("Firewall Statistics");
    gtk_widget_add_css_class(title, "title-text");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(header), title);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(header), spacer);

    GtkWidget *reset_btn = gtk_button_new_with_label("Reset");
    g_signal_connect(reset_btn, "clicked", G_CALLBACK(on_reset_stats), NULL);
    gtk_box_append(GTK_BOX(header), reset_btn);
    gtk_box_append(GTK_BOX(page), header);

    // Row 1: Main stats
    GtkWidget *row1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(row1), create_stat_card("Total Packets", &total_label));
    gtk_box_append(GTK_BOX(row1), create_stat_card("Allowed", &allowed_label));
    gtk_box_append(GTK_BOX(row1), create_stat_card("Blocked", &blocked_label));
    gtk_box_append(GTK_BOX(row1), create_stat_card("Uptime", &uptime_label));
    gtk_box_append(GTK_BOX(page), row1);

    // Row 2: Protocol stats
    GtkWidget *row2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(row2), create_stat_card("TCP", &tcp_label));
    gtk_box_append(GTK_BOX(row2), create_stat_card("UDP", &udp_label));
    gtk_box_append(GTK_BOX(row2), create_stat_card("ICMP", &icmp_label));
    gtk_box_append(GTK_BOX(row2), create_stat_card("ARP", &arp_label));
    gtk_box_append(GTK_BOX(page), row2);

    // Row 3: Throughput
    GtkWidget *row3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_append(GTK_BOX(row3), create_stat_card("Packets/sec", &pps_label));
    gtk_box_append(GTK_BOX(row3), create_stat_card("Bandwidth", &bps_label));
    gtk_box_append(GTK_BOX(page), row3);

    // Chart
    chart_area = gtk_drawing_area_new();
    gtk_widget_set_size_request(chart_area, -1, 250);
    gtk_widget_set_vexpand(chart_area, TRUE);
    gtk_widget_add_css_class(chart_area, "chart-area");
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(chart_area),
                                   draw_chart, NULL, NULL);

    GtkWidget *chart_frame = gtk_frame_new(NULL);
    gtk_widget_add_css_class(chart_frame, "card");
    gtk_frame_set_child(GTK_FRAME(chart_frame), chart_area);
    gtk_box_append(GTK_BOX(page), chart_frame);

    return page;
}
