#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "firewall.h"
#include "dpi.h"
#include "logger.h"

int fw_save_config(firewall_ctx_t *ctx, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    fprintf(fp, "# FlameWall Configuration\n");
    fprintf(fp, "# Generated automatically\n\n");

    fprintf(fp, "[settings]\n");
    fprintf(fp, "default_policy=%s\n", action_to_string(ctx->default_policy));
    fprintf(fp, "interface=%s\n", ctx->interface);
    fprintf(fp, "engine=%d\n", ctx->engine);
    fprintf(fp, "log_to_file=%d\n", ctx->log_to_file);
    fprintf(fp, "log_file=%s\n\n", ctx->log_file);

    pthread_mutex_lock(&ctx->rules_lock);
    for (int i = 0; i < ctx->rule_count; i++) {
        fw_rule_t *r = &ctx->rules[i];
        char addr[INET_ADDRSTRLEN];

        fprintf(fp, "[rule]\n");
        fprintf(fp, "id=%d\n", r->id);
        fprintf(fp, "enabled=%d\n", r->enabled);
        fprintf(fp, "type=%s\n", rule_type_to_string(r->type));
        fprintf(fp, "action=%s\n", action_to_string(r->action));
        fprintf(fp, "priority=%d\n", r->priority);
        fprintf(fp, "description=%s\n", r->description);

        if (r->mac_set) {
            char mac[18];
            mac_to_string(r->mac, mac);
            fprintf(fp, "mac=%s\n", mac);
        }

        if (r->ip) {
            inet_ntop(AF_INET, &r->ip, addr, sizeof(addr));
            fprintf(fp, "ip=%s\n", addr);
        }
        if (r->ip_mask) {
            inet_ntop(AF_INET, &r->ip_mask, addr, sizeof(addr));
            fprintf(fp, "mask=%s\n", addr);
        }
        if (r->ip_end) {
            inet_ntop(AF_INET, &r->ip_end, addr, sizeof(addr));
            fprintf(fp, "ip_end=%s\n", addr);
        }

        if (r->port) fprintf(fp, "port=%d\n", r->port);
        if (r->port_end) fprintf(fp, "port_end=%d\n", r->port_end);
        if (r->protocol) fprintf(fp, "protocol=%d\n", r->protocol);
        if (r->ethertype) fprintf(fp, "ethertype=0x%04x\n", r->ethertype);

        if (strlen(r->regex_pattern) > 0)
            fprintf(fp, "regex=%s\n", r->regex_pattern);
        if (r->content_len > 0)
            fprintf(fp, "content=%s\n", r->content_match);

        if (r->max_packets_per_sec)
            fprintf(fp, "max_pps=%d\n", r->max_packets_per_sec);
        if (r->max_bytes_per_sec)
            fprintf(fp, "max_bps=%d\n", r->max_bytes_per_sec);

        fprintf(fp, "\n");
    }
    pthread_mutex_unlock(&ctx->rules_lock);

    fclose(fp);
    return 0;
}

static fw_action_t string_to_action(const char *str) {
    if (strcmp(str, "BLOCK") == 0) return ACTION_BLOCK;
    if (strcmp(str, "LOG") == 0) return ACTION_LOG_ONLY;
    if (strcmp(str, "RATE_LIMIT") == 0) return ACTION_RATE_LIMIT;
    return ACTION_ALLOW;
}

static rule_type_t string_to_rule_type(const char *str) {
    if (strcmp(str, "MAC_SRC") == 0) return RULE_MAC_SRC;
    if (strcmp(str, "MAC_DST") == 0) return RULE_MAC_DST;
    if (strcmp(str, "IP_SRC") == 0) return RULE_IP_SRC;
    if (strcmp(str, "IP_DST") == 0) return RULE_IP_DST;
    if (strcmp(str, "IP_RANGE") == 0) return RULE_IP_RANGE;
    if (strcmp(str, "PORT_SRC") == 0) return RULE_PORT_SRC;
    if (strcmp(str, "PORT_DST") == 0) return RULE_PORT_DST;
    if (strcmp(str, "PORT_RANGE") == 0) return RULE_PORT_RANGE;
    if (strcmp(str, "PROTOCOL") == 0) return RULE_PROTOCOL;
    if (strcmp(str, "ETHERTYPE") == 0) return RULE_ETHERTYPE;
    if (strcmp(str, "DPI_REGEX") == 0) return RULE_DPI_REGEX;
    if (strcmp(str, "DPI_CONTENT") == 0) return RULE_DPI_CONTENT;
    if (strcmp(str, "RATE_LIMIT") == 0) return RULE_RATE_LIMIT;
    return RULE_IP_SRC;
}

int fw_load_config(firewall_ctx_t *ctx, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;

    fw_clear_rules(ctx);
    ctx->next_rule_id = 0;
    snprintf(ctx->config_file, sizeof(ctx->config_file), "%s", filename);

    char line[2048];
    fw_rule_t current_rule;
    memset(&current_rule, 0, sizeof(current_rule));
    bool in_rule = false;

    while (fgets(line, sizeof(line), fp)) {
        // Remove newline / stray CR
        line[strcspn(line, "\r\n")] = 0;

        // Skip comments and empty
        if (line[0] == '#' || line[0] == '\0') continue;

        if (strcmp(line, "[settings]") == 0) {
            if (in_rule) fw_add_rule(ctx, &current_rule);
            in_rule = false;
            continue;
        }

        if (strcmp(line, "[rule]") == 0) {
            if (in_rule) fw_add_rule(ctx, &current_rule);
            memset(&current_rule, 0, sizeof(fw_rule_t));
            current_rule.enabled = true;
            current_rule.priority = 100;
            in_rule = true;
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        if (!in_rule) {
            // Settings
            if (strcmp(key, "default_policy") == 0)
                ctx->default_policy = string_to_action(val);
            else if (strcmp(key, "interface") == 0)
                snprintf(ctx->interface, MAX_IFACE_NAME, "%s", val);
            else if (strcmp(key, "engine") == 0)
                ctx->engine = (engine_t)atoi(val);
            else if (strcmp(key, "log_to_file") == 0)
                ctx->log_to_file = atoi(val) != 0;
            else if (strcmp(key, "log_file") == 0)
                snprintf(ctx->log_file, sizeof(ctx->log_file), "%s", val);
        } else {
            // Rule fields
            if (strcmp(key, "enabled") == 0)
                current_rule.enabled = atoi(val) != 0;
            else if (strcmp(key, "type") == 0)
                current_rule.type = string_to_rule_type(val);
            else if (strcmp(key, "action") == 0)
                current_rule.action = string_to_action(val);
            else if (strcmp(key, "priority") == 0)
                current_rule.priority = atoi(val);
            else if (strcmp(key, "description") == 0)
                snprintf(current_rule.description, MAX_DESC_LEN, "%s", val);
            else if (strcmp(key, "mac") == 0) {
                string_to_mac(val, current_rule.mac);
                current_rule.mac_set = true;
            }
            else if (strcmp(key, "ip") == 0)
                current_rule.ip = inet_addr(val);
            else if (strcmp(key, "mask") == 0)
                current_rule.ip_mask = inet_addr(val);
            else if (strcmp(key, "ip_end") == 0)
                current_rule.ip_end = inet_addr(val);
            else if (strcmp(key, "port") == 0)
                current_rule.port = (uint16_t)atoi(val);
            else if (strcmp(key, "port_end") == 0)
                current_rule.port_end = (uint16_t)atoi(val);
            else if (strcmp(key, "protocol") == 0)
                current_rule.protocol = (uint8_t)atoi(val);
            else if (strcmp(key, "ethertype") == 0)
                current_rule.ethertype = (uint16_t)strtol(val, NULL, 16);
            else if (strcmp(key, "regex") == 0)
                snprintf(current_rule.regex_pattern, MAX_REGEX_LEN, "%s", val);
            else if (strcmp(key, "content") == 0) {
                snprintf(current_rule.content_match, MAX_PAYLOAD_LEN, "%s", val);
                current_rule.content_len = (int)strlen(current_rule.content_match);
            }
            else if (strcmp(key, "max_pps") == 0)
                current_rule.max_packets_per_sec = atoi(val);
            else if (strcmp(key, "max_bps") == 0)
                current_rule.max_bytes_per_sec = atoi(val);
        }
    }

    // Add last rule
    if (in_rule) fw_add_rule(ctx, &current_rule);

    fclose(fp);
    return 0;
}

int logger_export_csv(firewall_ctx_t *ctx, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;

    fprintf(fp, "Timestamp,Action,SrcMAC,DstMAC,SrcIP,DstIP,SrcPort,DstPort,Protocol,Reason,Size\n");

    pthread_mutex_lock(&ctx->log_lock);
    // Walk the circular buffer oldest-first.
    int start = (ctx->log_count == MAX_LOG_ENTRIES)
                ? (ctx->log_index % MAX_LOG_ENTRIES) : 0;
    for (int n = 0; n < ctx->log_count; n++) {
        log_entry_t *e = &ctx->logs[(start + n) % MAX_LOG_ENTRIES];
        fprintf(fp, "%ld,%s,%s,%s,%s,%s,%d,%d,%s,\"%s\",%d\n",
                (long)e->timestamp, action_to_string(e->action),
                e->src_mac, e->dst_mac, e->src_ip, e->dst_ip,
                e->src_port, e->dst_port, e->protocol,
                e->reason, e->packet_size);
    }
    pthread_mutex_unlock(&ctx->log_lock);

    fclose(fp);
    return 0;
}
