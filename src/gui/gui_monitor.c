#include <gtk/gtk.h>
#include <string.h>
#include <time.h>
#include "firewall.h"
#include "logger.h"

extern firewall_ctx_t *g_fw;

static GtkTextBuffer *log_buffer = NULL;
static GtkWidget *log_view = NULL;
static int last_log_index = 0;

// Keep the on-screen scrollback bounded; the full history lives in ctx->logs.
#define MAX_VIEW_LINES 2000

static void trim_log_view(void) {
    int lines = gtk_text_buffer_get_line_count(log_buffer);
    if (lines <= MAX_VIEW_LINES) return;

    GtkTextIter start, cut;
    gtk_text_buffer_get_start_iter(log_buffer, &start);
    gtk_text_buffer_get_iter_at_line(log_buffer, &cut, lines - MAX_VIEW_LINES);
    gtk_text_buffer_delete(log_buffer, &start, &cut);
}

static gboolean update_monitor(gpointer data) {
    firewall_ctx_t *ctx = (firewall_ctx_t *)data;
    if (!log_buffer) return G_SOURCE_CONTINUE;

    pthread_mutex_lock(&ctx->log_lock);

    // If we fell further behind than the ring holds, skip what was overwritten.
    if (ctx->log_index - last_log_index > MAX_LOG_ENTRIES)
        last_log_index = ctx->log_index - MAX_LOG_ENTRIES;

    bool appended = false;
    while (last_log_index < ctx->log_index) {
        int idx = last_log_index % MAX_LOG_ENTRIES;
        log_entry_t *e = &ctx->logs[idx];

        char line[640];
        char timestr[32];
        struct tm tmbuf;
        localtime_r(&e->timestamp, &tmbuf);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", &tmbuf);

        const char *color_tag = "allow";
        switch (e->action) {
            case ACTION_BLOCK:      color_tag = "block"; break;
            case ACTION_ALLOW:      color_tag = "allow"; break;
            case ACTION_LOG_ONLY:   color_tag = "log";   break;
            case ACTION_RATE_LIMIT: color_tag = "rate";  break;
        }

        snprintf(line, sizeof(line),
                 "[%s] %-10s %-5s %s:%d -> %s:%d (%s) %s [%dB]\n",
                 timestr, action_to_string(e->action), e->protocol,
                 e->src_ip, e->src_port, e->dst_ip, e->dst_port,
                 e->src_mac, e->reason, e->packet_size);

        GtkTextIter end;
        gtk_text_buffer_get_end_iter(log_buffer, &end);
        gtk_text_buffer_insert_with_tags_by_name(log_buffer, &end,
                                                 line, -1, color_tag, NULL);
        appended = true;
        last_log_index++;
    }
    pthread_mutex_unlock(&ctx->log_lock);

    if (!appended) return G_SOURCE_CONTINUE;

    trim_log_view();

    // Auto-scroll
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(log_buffer, &end);
    GtkTextMark *mark = gtk_text_buffer_get_mark(log_buffer, "scroll_end");
    if (!mark)
        mark = gtk_text_buffer_create_mark(log_buffer, "scroll_end", &end, FALSE);
    else
        gtk_text_buffer_move_mark(log_buffer, mark, &end);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(log_view), mark);

    return G_SOURCE_CONTINUE;
}

void start_monitor_updates(firewall_ctx_t *ctx) {
    g_timeout_add(500, update_monitor, ctx);
}

static void on_clear_log(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    if (!log_buffer) return;
    gtk_text_buffer_set_text(log_buffer, "", 0);
    pthread_mutex_lock(&g_fw->log_lock);
    last_log_index = g_fw->log_index;
    pthread_mutex_unlock(&g_fw->log_lock);
}

static void on_export_csv(GtkButton *btn, gpointer data) {
    (void)data;
    const char *path = "flamewall_logs.csv";
    char msg[256];

    if (logger_export_csv(g_fw, path) == 0)
        snprintf(msg, sizeof(msg), "Exported the log buffer to %s", path);
    else
        snprintf(msg, sizeof(msg), "Could not write %s", path);

    GtkAlertDialog *alert = gtk_alert_dialog_new("%s", msg);
    gtk_alert_dialog_show(alert, GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(btn))));
    g_object_unref(alert);
}

GtkWidget *create_monitor_page(firewall_ctx_t *ctx) {
    (void)ctx;
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);
    gtk_widget_set_margin_top(page, 20);
    gtk_widget_set_margin_bottom(page, 20);

    // Title bar
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *title = gtk_label_new("Live Traffic Monitor");
    gtk_widget_add_css_class(title, "title-text");
    gtk_box_append(GTK_BOX(header), title);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(header), spacer);

    GtkWidget *clear_btn = gtk_button_new_with_label("Clear");
    g_signal_connect(clear_btn, "clicked", G_CALLBACK(on_clear_log), NULL);
    gtk_box_append(GTK_BOX(header), clear_btn);

    GtkWidget *export_btn = gtk_button_new_with_label("Export CSV");
    g_signal_connect(export_btn, "clicked", G_CALLBACK(on_export_csv), NULL);
    gtk_box_append(GTK_BOX(header), export_btn);

    gtk_box_append(GTK_BOX(page), header);

    // Log text view
    log_buffer = gtk_text_buffer_new(NULL);

    // Color tags
    gtk_text_buffer_create_tag(log_buffer, "block", "foreground", "#e94560", NULL);
    gtk_text_buffer_create_tag(log_buffer, "allow", "foreground", "#00ff88", NULL);
    gtk_text_buffer_create_tag(log_buffer, "log",   "foreground", "#ffcc00", NULL);
    gtk_text_buffer_create_tag(log_buffer, "rate",  "foreground", "#ff8800", NULL);

    log_view = gtk_text_view_new_with_buffer(log_buffer);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(log_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(log_view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(log_view), GTK_WRAP_WORD_CHAR);
    gtk_widget_add_css_class(log_view, "log-view");

    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), log_view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_add_css_class(scroll, "card");

    gtk_box_append(GTK_BOX(page), scroll);

    return page;
}
