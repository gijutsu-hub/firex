#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "firewall.h"
#include "dpi.h"

extern firewall_ctx_t *g_fw;

// Store list for updating
static GtkListStore *rules_store = NULL;
static GtkWidget *rules_tree = NULL;

// ========== REFRESH RULES LIST ==========
static void refresh_rules_list(void) {
    if (!rules_store) return;
    gtk_list_store_clear(rules_store);

    pthread_mutex_lock(&g_fw->rules_lock);
    for (int i = 0; i < g_fw->rule_count; i++) {
        fw_rule_t *r = &g_fw->rules[i];
        GtkTreeIter iter;
        gtk_list_store_append(rules_store, &iter);

        char detail[160] = "";
        struct in_addr addr;

        switch (r->type) {
            case RULE_MAC_SRC:
            case RULE_MAC_DST:
                mac_to_string(r->mac, detail);
                break;
            case RULE_IP_SRC:
            case RULE_IP_DST:
                addr.s_addr = r->ip;
                inet_ntop(AF_INET, &addr, detail, INET_ADDRSTRLEN);
                break;
            case RULE_IP_RANGE: {
                char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
                addr.s_addr = r->ip;
                inet_ntop(AF_INET, &addr, a, sizeof(a));
                addr.s_addr = r->ip_end;
                inet_ntop(AF_INET, &addr, b, sizeof(b));
                snprintf(detail, sizeof(detail), "%s - %s", a, b);
                break;
            }
            case RULE_PORT_SRC:
            case RULE_PORT_DST:
                snprintf(detail, sizeof(detail), "%d", r->port);
                break;
            case RULE_PORT_RANGE:
                snprintf(detail, sizeof(detail), "%d-%d", r->port, r->port_end);
                break;
            case RULE_PROTOCOL:
                snprintf(detail, sizeof(detail), "%s", protocol_to_string(r->protocol));
                break;
            case RULE_ETHERTYPE:
                snprintf(detail, sizeof(detail), "0x%04x", r->ethertype);
                break;
            case RULE_DPI_REGEX:
                snprintf(detail, sizeof(detail), "%s", r->regex_pattern);
                break;
            case RULE_DPI_CONTENT:
                snprintf(detail, sizeof(detail), "%s", r->content_match);
                break;
            case RULE_RATE_LIMIT:
                snprintf(detail, sizeof(detail), "%d pps / %d bps",
                         r->max_packets_per_sec, r->max_bytes_per_sec);
                break;
            default:
                snprintf(detail, sizeof(detail), "-");
        }

        char hits[32];
        snprintf(hits, sizeof(hits), "%lu", r->hit_count);

        gtk_list_store_set(rules_store, &iter,
            0, r->id,
            1, r->enabled ? "Yes" : "No",
            2, rule_type_to_string(r->type),
            3, action_to_string(r->action),
            4, detail,
            5, r->description,
            6, r->priority,
            7, hits,
            -1);
    }
    pthread_mutex_unlock(&g_fw->rules_lock);
}

// ========== ADD RULE DIALOG ==========
typedef struct {
    GtkWidget *dialog;
    GtkWidget *type_dropdown;
    GtkWidget *action_dropdown;
    GtkWidget *value_entry;
    GtkWidget *value2_entry;  // For ranges
    GtkWidget *desc_entry;
    GtkWidget *priority_spin;
    GtkWidget *protocol_dropdown;
    GtkWidget *pps_spin;
    GtkWidget *bps_spin;
    // Dynamic widgets
    GtkWidget *value_label;
    GtkWidget *value2_label;
    GtkWidget *protocol_label;
    GtkWidget *extra_box;
} add_rule_dialog_t;

static const char *rule_types[] = {
    "Source MAC", "Dest MAC", "Source IP", "Dest IP",
    "Source Port", "Dest Port", "Port Range", "Protocol",
    "DPI Regex", "DPI Content", "Rate Limit", NULL
};

static const char *actions[] = {"ALLOW", "BLOCK", "LOG Only", "Rate Limit", NULL};
static const char *protocols[] = {"TCP", "UDP", "ICMP", "Any", NULL};

static void apply_rule_type_ui(add_rule_dialog_t *d, int selected) {
    gtk_widget_set_visible(d->value2_entry, FALSE);
    gtk_widget_set_visible(d->value2_label, FALSE);
    gtk_widget_set_visible(d->extra_box, FALSE);
    gtk_widget_set_visible(d->protocol_dropdown, selected == 7);
    gtk_widget_set_visible(d->protocol_label, selected == 7);
    gtk_widget_set_visible(d->value_entry, selected != 7);
    gtk_widget_set_visible(d->value_label, selected != 7);

    switch (selected) {
        case 0: case 1: // MAC
            gtk_label_set_text(GTK_LABEL(d->value_label), "MAC Address:");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value_entry), "aa:bb:cc:dd:ee:ff");
            break;
        case 2: case 3: // IP
            gtk_label_set_text(GTK_LABEL(d->value_label), "IP Address:");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value_entry), "192.168.1.100");
            break;
        case 4: case 5: // Port
            gtk_label_set_text(GTK_LABEL(d->value_label), "Port:");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value_entry), "80");
            break;
        case 6: // Port Range
            gtk_label_set_text(GTK_LABEL(d->value_label), "Start Port:");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value_entry), "1024");
            gtk_widget_set_visible(d->value2_entry, TRUE);
            gtk_widget_set_visible(d->value2_label, TRUE);
            gtk_label_set_text(GTK_LABEL(d->value2_label), "End Port:");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value2_entry), "65535");
            break;
        case 7: // Protocol
            break;
        case 8: // DPI Regex
            gtk_label_set_text(GTK_LABEL(d->value_label), "Regex Pattern:");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value_entry),
                "(GET|POST)[[:space:]]+/admin");
            break;
        case 9: // DPI Content
            gtk_label_set_text(GTK_LABEL(d->value_label), "Content String:");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value_entry),
                "malware_payload");
            break;
        case 10: // Rate limit
            gtk_label_set_text(GTK_LABEL(d->value_label), "Source IP (or * for all):");
            gtk_entry_set_placeholder_text(GTK_ENTRY(d->value_entry), "*");
            gtk_widget_set_visible(d->extra_box, TRUE);
            break;
        default:
            break;
    }
}

static void on_rule_type_changed(GtkDropDown *dropdown, GParamSpec *pspec, gpointer data) {
    (void)pspec;
    apply_rule_type_ui((add_rule_dialog_t *)data,
                       (int)gtk_drop_down_get_selected(dropdown));
}

static void show_error(GtkWidget *parent, const char *msg) {
    GtkAlertDialog *alert = gtk_alert_dialog_new("%s", msg);
    gtk_alert_dialog_show(alert, GTK_WINDOW(gtk_widget_get_root(parent)));
    g_object_unref(alert);
}

static void on_add_rule_response(GtkDialog *dialog, int response, gpointer data) {
    add_rule_dialog_t *d = (add_rule_dialog_t *)data;

    if (response == GTK_RESPONSE_ACCEPT) {
        fw_rule_t rule;
        memset(&rule, 0, sizeof(rule));
        rule.enabled = true;

        int type_idx = (int)gtk_drop_down_get_selected(GTK_DROP_DOWN(d->type_dropdown));
        int action_idx = (int)gtk_drop_down_get_selected(GTK_DROP_DOWN(d->action_dropdown));

        const char *value = gtk_editable_get_text(GTK_EDITABLE(d->value_entry));
        const char *desc = gtk_editable_get_text(GTK_EDITABLE(d->desc_entry));
        rule.priority = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(d->priority_spin));

        snprintf(rule.description, MAX_DESC_LEN, "%s", desc);

        // Map action
        switch (action_idx) {
            case 0: rule.action = ACTION_ALLOW; break;
            case 1: rule.action = ACTION_BLOCK; break;
            case 2: rule.action = ACTION_LOG_ONLY; break;
            case 3: rule.action = ACTION_RATE_LIMIT; break;
            default: rule.action = ACTION_ALLOW; break;
        }

        const char *err = NULL;

        // Map type and value
        switch (type_idx) {
            case 0: // Src MAC
            case 1: // Dst MAC
                rule.type = (type_idx == 0) ? RULE_MAC_SRC : RULE_MAC_DST;
                {
                    unsigned char probe[6];
                    if (sscanf(value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                               &probe[0], &probe[1], &probe[2],
                               &probe[3], &probe[4], &probe[5]) != 6) {
                        err = "Enter a MAC address as aa:bb:cc:dd:ee:ff";
                    } else {
                        memcpy(rule.mac, probe, 6);
                        rule.mac_set = true;
                    }
                }
                break;
            case 2: // Src IP
            case 3: // Dst IP
                rule.type = (type_idx == 2) ? RULE_IP_SRC : RULE_IP_DST;
                {
                    struct in_addr a;
                    if (inet_pton(AF_INET, value, &a) != 1)
                        err = "Enter a dotted-quad IPv4 address, e.g. 192.168.1.100";
                    else
                        rule.ip = a.s_addr;
                }
                break;
            case 4: // Src Port
            case 5: // Dst Port
                rule.type = (type_idx == 4) ? RULE_PORT_SRC : RULE_PORT_DST;
                {
                    int p = atoi(value);
                    if (p < 1 || p > 65535) err = "Port must be between 1 and 65535";
                    else rule.port = (uint16_t)p;
                }
                break;
            case 6: // Port Range
                rule.type = RULE_PORT_RANGE;
                {
                    int p1 = atoi(value);
                    int p2 = atoi(gtk_editable_get_text(GTK_EDITABLE(d->value2_entry)));
                    if (p1 < 1 || p1 > 65535 || p2 < 1 || p2 > 65535 || p2 < p1)
                        err = "Enter a valid port range (1-65535, end >= start)";
                    else {
                        rule.port = (uint16_t)p1;
                        rule.port_end = (uint16_t)p2;
                    }
                }
                break;
            case 7: // Protocol
            {
                rule.type = RULE_PROTOCOL;
                int pidx = (int)gtk_drop_down_get_selected(
                    GTK_DROP_DOWN(d->protocol_dropdown));
                switch (pidx) {
                    case 0: rule.protocol = IPPROTO_TCP; break;
                    case 1: rule.protocol = IPPROTO_UDP; break;
                    case 2: rule.protocol = IPPROTO_ICMP; break;
                    default: rule.protocol = 0; break;
                }
                break;
            }
            case 8: // DPI Regex
                rule.type = RULE_DPI_REGEX;
                if (!value[0]) err = "Enter a POSIX extended regular expression";
                else snprintf(rule.regex_pattern, MAX_REGEX_LEN, "%s", value);
                break;
            case 9: // DPI Content
                rule.type = RULE_DPI_CONTENT;
                if (!value[0]) err = "Enter the literal string to search for";
                else {
                    snprintf(rule.content_match, MAX_PAYLOAD_LEN, "%s", value);
                    rule.content_len = (int)strlen(rule.content_match);
                }
                break;
            case 10: // Rate limit
                rule.type = RULE_RATE_LIMIT;
                if (value[0] && strcmp(value, "*") != 0) {
                    struct in_addr a;
                    if (inet_pton(AF_INET, value, &a) != 1)
                        err = "Enter an IPv4 address, or * to limit every source";
                    else
                        rule.ip = a.s_addr;
                }
                rule.max_packets_per_sec = gtk_spin_button_get_value_as_int(
                    GTK_SPIN_BUTTON(d->pps_spin));
                rule.max_bytes_per_sec = gtk_spin_button_get_value_as_int(
                    GTK_SPIN_BUTTON(d->bps_spin));
                rule.action = ACTION_RATE_LIMIT;
                break;
            default:
                err = "Unsupported rule type";
                break;
        }

        if (err) {
            show_error(GTK_WIDGET(dialog), err);
            return;  // keep the dialog open so the value can be corrected
        }

        if (fw_add_rule(g_fw, &rule) < 0) {
            show_error(GTK_WIDGET(dialog),
                       "Rule rejected: the table is full, or the regex did not compile.");
            return;
        }
        refresh_rules_list();
    }

    gtk_window_destroy(GTK_WINDOW(dialog));
    free(d);
}

// ========== QUICK PRESETS ==========
static void on_preset_clicked(GtkButton *btn, gpointer data) {
    (void)data;
    add_rule_dialog_t *d = g_object_get_data(G_OBJECT(btn), "dialog");
    int preset = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(btn), "preset_id"));

    switch (preset) {
        case 0: // Block Ping
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->type_dropdown), 7);
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->action_dropdown), 1);
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->protocol_dropdown), 2);
            gtk_editable_set_text(GTK_EDITABLE(d->desc_entry), "Block ICMP Ping");
            break;
        case 1: // Block Telnet
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->type_dropdown), 5);
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->action_dropdown), 1);
            gtk_editable_set_text(GTK_EDITABLE(d->value_entry), "23");
            gtk_editable_set_text(GTK_EDITABLE(d->desc_entry), "Block Telnet");
            break;
        case 2: // Block SSH
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->type_dropdown), 5);
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->action_dropdown), 1);
            gtk_editable_set_text(GTK_EDITABLE(d->value_entry), "22");
            gtk_editable_set_text(GTK_EDITABLE(d->desc_entry), "Block SSH");
            break;
        case 3: // Block HTTP
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->type_dropdown), 5);
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->action_dropdown), 1);
            gtk_editable_set_text(GTK_EDITABLE(d->value_entry), "80");
            gtk_editable_set_text(GTK_EDITABLE(d->desc_entry), "Block HTTP");
            break;
        case 4: // DPI SQL Injection
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->type_dropdown), 8);
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->action_dropdown), 1);
            gtk_editable_set_text(GTK_EDITABLE(d->value_entry),
                "(SELECT|UNION|INSERT|DELETE|DROP).*FROM");
            gtk_editable_set_text(GTK_EDITABLE(d->desc_entry),
                "Block SQL Injection attempts");
            break;
        case 5: // DPI XSS
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->type_dropdown), 8);
            gtk_drop_down_set_selected(GTK_DROP_DOWN(d->action_dropdown), 1);
            gtk_editable_set_text(GTK_EDITABLE(d->value_entry),
                "<script[^>]*>|javascript:|on(load|click|error)=");
            gtk_editable_set_text(GTK_EDITABLE(d->desc_entry),
                "Block XSS attempts");
            break;
        default:
            break;
    }
}

static void show_add_rule_dialog(GtkWidget *btn, gpointer data) {
    (void)data;
    add_rule_dialog_t *d = calloc(1, sizeof(add_rule_dialog_t));
    if (!d) return;

    d->dialog = gtk_dialog_new_with_buttons(
        "Add Firewall Rule",
        GTK_WINDOW(gtk_widget_get_root(btn)),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        "Add Rule", GTK_RESPONSE_ACCEPT,
        NULL);

    gtk_window_set_default_size(GTK_WINDOW(d->dialog), 520, 620);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(d->dialog));
    gtk_widget_set_margin_start(content, 20);
    gtk_widget_set_margin_end(content, 20);
    gtk_widget_set_margin_top(content, 15);
    gtk_widget_set_margin_bottom(content, 15);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);

    int row = 0;

    // Rule Type
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Rule Type:"), 0, row, 1, 1);
    d->type_dropdown = gtk_drop_down_new_from_strings(rule_types);
    gtk_widget_set_hexpand(d->type_dropdown, TRUE);
    gtk_grid_attach(GTK_GRID(grid), d->type_dropdown, 1, row++, 1, 1);

    // Action
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Action:"), 0, row, 1, 1);
    d->action_dropdown = gtk_drop_down_new_from_strings(actions);
    gtk_grid_attach(GTK_GRID(grid), d->action_dropdown, 1, row++, 1, 1);

    // Priority
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Priority:"), 0, row, 1, 1);
    d->priority_spin = gtk_spin_button_new_with_range(0, 999, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(d->priority_spin), 100);
    gtk_grid_attach(GTK_GRID(grid), d->priority_spin, 1, row++, 1, 1);

    // Value
    d->value_label = gtk_label_new("Value:");
    gtk_grid_attach(GTK_GRID(grid), d->value_label, 0, row, 1, 1);
    d->value_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), d->value_entry, 1, row++, 1, 1);

    // Value2 (for ranges)
    d->value2_label = gtk_label_new("End Value:");
    gtk_grid_attach(GTK_GRID(grid), d->value2_label, 0, row, 1, 1);
    d->value2_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), d->value2_entry, 1, row++, 1, 1);

    // Protocol dropdown (only for the protocol rule type)
    d->protocol_label = gtk_label_new("Protocol:");
    gtk_grid_attach(GTK_GRID(grid), d->protocol_label, 0, row, 1, 1);
    d->protocol_dropdown = gtk_drop_down_new_from_strings(protocols);
    gtk_grid_attach(GTK_GRID(grid), d->protocol_dropdown, 1, row++, 1, 1);

    // Extra box for rate limiting
    d->extra_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);

    GtkWidget *pps_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(pps_box), gtk_label_new("Max PPS:"));
    d->pps_spin = gtk_spin_button_new_with_range(0, 100000, 10);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(d->pps_spin), 100);
    gtk_box_append(GTK_BOX(pps_box), d->pps_spin);
    gtk_box_append(GTK_BOX(d->extra_box), pps_box);

    GtkWidget *bps_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(bps_box), gtk_label_new("Max BPS:"));
    d->bps_spin = gtk_spin_button_new_with_range(0, 1000000000, 1000);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(d->bps_spin), 1000000);
    gtk_box_append(GTK_BOX(bps_box), d->bps_spin);
    gtk_box_append(GTK_BOX(d->extra_box), bps_box);

    gtk_grid_attach(GTK_GRID(grid), d->extra_box, 0, row++, 2, 1);

    // Description
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Description:"), 0, row, 1, 1);
    d->desc_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(d->desc_entry), "Block malicious traffic");
    gtk_grid_attach(GTK_GRID(grid), d->desc_entry, 1, row++, 1, 1);

    // === Preset buttons ===
    GtkWidget *presets_label = gtk_label_new("Quick Presets:");
    gtk_widget_set_margin_top(presets_label, 10);
    gtk_grid_attach(GTK_GRID(grid), presets_label, 0, row++, 2, 1);

    GtkWidget *preset_box = gtk_flow_box_new();
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(preset_box), 3);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(preset_box), GTK_SELECTION_NONE);

    static const char *preset_labels[] = {
        "Block Ping", "Block Telnet",
        "Block SSH",  "Block HTTP",
        "DPI: SQL Inject", "DPI: XSS"
    };

    for (int i = 0; i < 6; i++) {
        GtkWidget *pbtn = gtk_button_new_with_label(preset_labels[i]);
        g_object_set_data(G_OBJECT(pbtn), "dialog", d);
        g_object_set_data(G_OBJECT(pbtn), "preset_id", GINT_TO_POINTER(i));
        g_signal_connect(pbtn, "clicked", G_CALLBACK(on_preset_clicked), NULL);
        gtk_flow_box_insert(GTK_FLOW_BOX(preset_box), pbtn, -1);
    }
    gtk_grid_attach(GTK_GRID(grid), preset_box, 0, row++, 2, 1);

    gtk_box_append(GTK_BOX(content), grid);

    // Connect type change, then set the initial field layout
    g_signal_connect(d->type_dropdown, "notify::selected",
                     G_CALLBACK(on_rule_type_changed), d);
    g_signal_connect(d->dialog, "response",
                     G_CALLBACK(on_add_rule_response), d);

    gtk_window_present(GTK_WINDOW(d->dialog));
    apply_rule_type_ui(d, 0);
}

// ========== SELECTED RULE HELPERS ==========
static bool get_selected_rule_id(int *id) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(rules_tree));
    GtkTreeIter iter;
    GtkTreeModel *model;

    if (gtk_tree_selection_get_selected(sel, &model, &iter)) {
        gtk_tree_model_get(model, &iter, 0, id, -1);
        return true;
    }
    return false;
}

static void on_delete_rule(GtkWidget *btn, gpointer data) {
    (void)btn; (void)data;
    int id;
    if (get_selected_rule_id(&id)) {
        fw_remove_rule(g_fw, id);
        refresh_rules_list();
    }
}

static void on_toggle_rule(GtkWidget *btn, gpointer data) {
    (void)btn; (void)data;
    int id;
    if (!get_selected_rule_id(&id)) return;

    bool now_enabled = false;
    pthread_mutex_lock(&g_fw->rules_lock);
    for (int i = 0; i < g_fw->rule_count; i++) {
        if (g_fw->rules[i].id == id) { now_enabled = g_fw->rules[i].enabled; break; }
    }
    pthread_mutex_unlock(&g_fw->rules_lock);

    fw_toggle_rule(g_fw, id, !now_enabled);
    refresh_rules_list();
}

// ========== SAVE/LOAD ==========
static void on_save_rules(GtkWidget *btn, gpointer data) {
    (void)data;
    if (fw_save_config(g_fw, "config/rules.conf") != 0)
        show_error(btn, "Could not write config/rules.conf");
}

static void on_load_rules(GtkWidget *btn, gpointer data) {
    (void)data;
    if (fw_load_config(g_fw, "config/rules.conf") != 0)
        show_error(btn, "Could not read config/rules.conf");
    refresh_rules_list();
}

// Hit counts move while the engine runs, so keep the table live.
static gboolean refresh_rules_tick(gpointer data) {
    (void)data;
    refresh_rules_list();
    return G_SOURCE_CONTINUE;
}

// ========== CREATE RULES PAGE ==========
GtkWidget *create_rules_page(firewall_ctx_t *ctx) {
    (void)ctx;
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);
    gtk_widget_set_margin_top(page, 20);
    gtk_widget_set_margin_bottom(page, 20);

    // Header
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *title = gtk_label_new("Firewall Rules");
    gtk_widget_add_css_class(title, "title-text");
    gtk_box_append(GTK_BOX(header), title);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(header), spacer);

    // Buttons
    GtkWidget *add_btn = gtk_button_new_with_label("Add Rule");
    gtk_widget_add_css_class(add_btn, "add-btn");
    g_signal_connect(add_btn, "clicked", G_CALLBACK(show_add_rule_dialog), NULL);
    gtk_box_append(GTK_BOX(header), add_btn);

    GtkWidget *toggle_btn = gtk_button_new_with_label("Toggle");
    g_signal_connect(toggle_btn, "clicked", G_CALLBACK(on_toggle_rule), NULL);
    gtk_box_append(GTK_BOX(header), toggle_btn);

    GtkWidget *del_btn = gtk_button_new_with_label("Delete");
    gtk_widget_add_css_class(del_btn, "stop-btn");
    g_signal_connect(del_btn, "clicked", G_CALLBACK(on_delete_rule), NULL);
    gtk_box_append(GTK_BOX(header), del_btn);

    GtkWidget *save_btn = gtk_button_new_with_label("Save");
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_save_rules), NULL);
    gtk_box_append(GTK_BOX(header), save_btn);

    GtkWidget *load_btn = gtk_button_new_with_label("Load");
    g_signal_connect(load_btn, "clicked", G_CALLBACK(on_load_rules), NULL);
    gtk_box_append(GTK_BOX(header), load_btn);

    gtk_box_append(GTK_BOX(page), header);

    // Rules table
    rules_store = gtk_list_store_new(8,
        G_TYPE_INT,     // ID
        G_TYPE_STRING,  // Enabled
        G_TYPE_STRING,  // Type
        G_TYPE_STRING,  // Action
        G_TYPE_STRING,  // Value
        G_TYPE_STRING,  // Description
        G_TYPE_INT,     // Priority
        G_TYPE_STRING   // Hits
    );

    rules_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(rules_store));
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(rules_tree),
                                 GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

    static const char *columns[] = {"ID", "On", "Type", "Action", "Value",
                                    "Description", "Priority", "Hits"};
    for (int i = 0; i < 8; i++) {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
            columns[i], renderer, "text", i, NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_sort_column_id(col, i);
        gtk_tree_view_append_column(GTK_TREE_VIEW(rules_tree), col);
    }

    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), rules_tree);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_add_css_class(scroll, "card");
    gtk_box_append(GTK_BOX(page), scroll);

    refresh_rules_list();
    g_timeout_add_seconds(2, refresh_rules_tick, NULL);
    return page;
}
