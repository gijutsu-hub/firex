/*
 * The desktop console's stylesheet.
 *
 * Kept apart from the window code because it is the part that gets
 * edited: every colour comes from include/brand.h, so a re-skin is one
 * header and a rebuild, and nothing here needs to know how the console
 * is assembled.
 */
#define _GNU_SOURCE
#include <gtk/gtk.h>

#include "brand.h"

// ========== CSS STYLING ==========
static const char *const default_css =
    "window { background-color: #1a1a2e; }"
    ".header-bar { background: linear-gradient(to right, #16213e, #0f3460); }"
    ".sidebar { background-color: #16213e; padding: 10px; }"
    ".sidebar button { "
    "  background: transparent; color: #e0e0e0; "
    "  border: none; padding: 12px 20px; margin: 2px 0; "
    "  font-size: 14px; border-radius: 8px; "
    "}"
    ".sidebar button:hover { background-color: #1a1a40; }"
    ".sidebar button:checked { "
    "  background: linear-gradient(135deg, #e94560, #533483); "
    "  color: white; font-weight: bold; "
    "}"
    ".card { "
    "  background-color: #16213e; border-radius: 12px; "
    "  padding: 20px; margin: 8px; "
    "}"
    ".stat-card { "
    "  background: linear-gradient(135deg, #0f3460, #16213e); "
    "  border-radius: 12px; padding: 15px; margin: 5px; "
    "}"
    ".stat-number { font-size: 28px; font-weight: bold; color: #e94560; }"
    ".stat-label { font-size: 12px; color: #8888aa; }"
    ".status-running { color: #00ff88; font-weight: bold; }"
    ".status-stopped { color: #e94560; font-weight: bold; }"
    ".rule-allow { color: #00ff88; }"
    ".rule-block { color: #e94560; }"
    ".rule-log { color: #ffcc00; }"
    ".title-text { font-size: 24px; font-weight: bold; color: white; }"
    ".subtitle-text { font-size: 14px; color: #8888aa; }"
    "label { color: #e0e0e0; }"
    "entry { "
    "  background-color: #0f3460; color: white; "
    "  border: 1px solid #533483; border-radius: 6px; "
    "  padding: 8px; "
    "}"
    "entry:focus { border-color: #e94560; }"
    "button.start-btn { "
    "  background: linear-gradient(135deg, #00ff88, #00cc66); "
    "  color: #1a1a2e; font-weight: bold; "
    "  border-radius: 8px; padding: 10px 20px; "
    "}"
    "button.stop-btn { "
    "  background: linear-gradient(135deg, #e94560, #c23152); "
    "  color: white; font-weight: bold; "
    "  border-radius: 8px; padding: 10px 20px; "
    "}"
    /* ---- sign-in screen ---- */
    ".login-root { background-color: " BRAND_COLOR_DARK "; }"
    ".login-left { background-color: " BRAND_COLOR_PANEL "; padding: 48px 40px; }"
    ".login-brand { font-size: 26px; font-weight: bold; color: "
        BRAND_COLOR_TEXT "; }"
    ".login-tagline { font-size: 11px; letter-spacing: 3px; color: "
        BRAND_COLOR_MUTED "; }"
    ".login-version { font-size: 11px; color: " BRAND_COLOR_MUTED "; }"
    ".login-net { padding: 14px 0 0 0; }"
    ".net-head { font-size: 10px; letter-spacing: 1.4px; font-weight: bold;"
    "  color: " BRAND_COLOR_MUTED "; margin-bottom: 4px; }"
    ".net-key { font-size: 12px; color: " BRAND_COLOR_MUTED ";"
    "  font-family: monospace; }"
    ".net-val { font-size: 12px; color: " BRAND_COLOR_TEXT ";"
    "  font-family: monospace; }"
    ".net-val-ok { font-size: 12px; color: " BRAND_COLOR_SUCCESS ";"
    "  font-family: monospace; }"
    ".net-val-warn { font-size: 12px; color: " BRAND_COLOR_WARNING ";"
    "  font-family: monospace; }"
    ".net-val-bad { font-size: 12px; color: " BRAND_COLOR_DANGER ";"
    "  font-family: monospace; font-weight: bold; }"
    ".login-card { background-color: " BRAND_COLOR_PANEL ";"
    "  border-radius: 14px; padding: 34px 32px; }"
    ".login-title { font-size: 22px; font-weight: bold; color: "
        BRAND_COLOR_TEXT "; }"
    ".login-sub { font-size: 12px; color: " BRAND_COLOR_MUTED "; }"
    ".login-label { font-size: 11px; color: " BRAND_COLOR_MUTED ";"
    "  margin-bottom: 4px; }"
    ".login-button { background: linear-gradient(135deg, "
        BRAND_COLOR_PRIMARY ", " BRAND_COLOR_SECONDARY ");"
    "  color: white; font-weight: bold; border-radius: 9px; padding: 12px; }"
    ".login-note { font-size: 12px; color: " BRAND_COLOR_MUTED "; }"
    ".login-error { font-size: 12px; color: " BRAND_COLOR_DANGER ";"
    "  font-weight: bold; }"
    ".login-by { font-size: 12px; font-weight: bold; color: "
        BRAND_COLOR_PRIMARY "; }"

    /* ---- appliance overview ---- */
    ".dash-page { padding: 22px; }"
    ".dash-title { font-size: 22px; font-weight: bold; color: "
        BRAND_COLOR_TEXT "; }"
    ".dash-refresh { padding: 6px 14px; border-radius: 8px; }"
    ".dash-banner { background-color: #3A1016; color: #FF8899;"
    "  border-radius: 10px; padding: 12px 14px; font-weight: bold; }"
    ".dash-tile { background-color: " BRAND_COLOR_PANEL ";"
    "  border-radius: 12px; padding: 14px 16px; }"
    ".dash-num { font-size: 24px; font-weight: bold; color: "
        BRAND_COLOR_TEXT "; }"
    ".dash-num.dash-ok { color: " BRAND_COLOR_SUCCESS "; }"
    ".dash-num.dash-warn { color: " BRAND_COLOR_WARNING "; }"
    ".dash-num.dash-bad { color: " BRAND_COLOR_DANGER "; }"
    ".dash-lab { font-size: 10px; letter-spacing: 1.1px; color: "
        BRAND_COLOR_MUTED "; }"
    ".dash-card { background-color: " BRAND_COLOR_PANEL ";"
    "  border-radius: 12px; padding: 16px 18px; }"
    ".dash-head { font-size: 12px; letter-spacing: 1.2px; font-weight: bold;"
    "  color: " BRAND_COLOR_MUTED "; }"
    ".dash-th { font-size: 10px; letter-spacing: 1.1px; font-weight: bold;"
    "  color: " BRAND_COLOR_MUTED "; }"
    ".dash-cell { font-size: 12px; color: " BRAND_COLOR_TEXT "; }"
    ".dash-cell-mono { font-size: 12px; color: " BRAND_COLOR_TEXT ";"
    "  font-family: monospace; }"
    ".dash-cell-mut { font-size: 11px; color: " BRAND_COLOR_MUTED "; }"
    ".dash-pill-ok { font-size: 11px; font-weight: bold; color: "
        BRAND_COLOR_SUCCESS "; }"
    ".dash-pill-bad { font-size: 11px; font-weight: bold; color: "
        BRAND_COLOR_DANGER "; }"
    ".dash-pill-mut { font-size: 11px; color: " BRAND_COLOR_MUTED "; }"
    ".dash-status { font-size: 11px; color: " BRAND_COLOR_MUTED ";"
    "  font-family: monospace; }"
    "button.add-btn { "
    "  background: linear-gradient(135deg, #533483, #0f3460); "
    "  color: white; border-radius: 8px; padding: 8px 16px; "
    "}"
    ".log-view { "
    "  background-color: #0d1117; color: #c9d1d9; "
    "  font-family: monospace; font-size: 12px; "
    "}"
    "treeview { background-color: #16213e; color: #e0e0e0; }"
    "treeview:selected { background-color: #533483; color: white; }"
    "columnview { background-color: #16213e; color: #e0e0e0; }"
    "columnview > header { background-color: #0f3460; color: white; }"
    ".chart-area { background-color: #0d1117; border-radius: 8px; }"
    "dropdown { background-color: #0f3460; color: white; }"
    "switch:checked slider { background-color: #00ff88; }";

/*
 * The built-in stylesheet is always the base; a file on disk is layered
 * over it at a higher priority.
 *
 * It used to be one or the other, with the file winning outright. That
 * meant a stylesheet written against an older build silently erased
 * every rule added since -- the screen came up unstyled with nothing
 * said about why. Layering keeps a partial or stale override to the
 * rules it actually mentions.
 *
 * The search path is fixed rather than relative, too: loading a theme
 * from the current directory made the console's appearance depend on
 * where it happened to be started from, which on the appliance is
 * whatever directory systemd chose.
 */
void gui_load_css(void) {
    GtkCssProvider *base = gtk_css_provider_new();
    gtk_css_provider_load_from_string(base, default_css);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(base),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(base);

    static const char *const overrides[] = {
        "/etc/firex/console.css",              /* operator's own    */
        "/usr/local/share/firex/flamewall.css",/* shipped with the image */
        "flamewall.css",                       /* a developer's tree */
        NULL
    };

    for (int i = 0; overrides[i]; i++) {
        gchar *css = NULL;
        if (!g_file_get_contents(overrides[i], &css, NULL, NULL)) continue;

        GtkCssProvider *over = gtk_css_provider_new();
        gtk_css_provider_load_from_string(over, css);
        gtk_style_context_add_provider_for_display(
            gdk_display_get_default(),
            GTK_STYLE_PROVIDER(over),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
        g_object_unref(over);
        g_free(css);
        g_message("console theme: layered %s over the built-in stylesheet",
                  overrides[i]);
        break;
    }
}


/* The built-in sheet, for anything that needs to style a widget without
 * going through a display -- the render harness, mainly. */
const char *gui_default_css(void) { return default_css; }
