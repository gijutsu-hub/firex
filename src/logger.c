#include <stdio.h>
#include <string.h>
#include "logger.h"

int logger_init(firewall_ctx_t *ctx, const char *log_file) {
    logger_close(ctx);

    if (!log_file || !log_file[0]) return -1;

    ctx->log_fp = fopen(log_file, "a");
    if (!ctx->log_fp) {
        perror("fopen(log_file)");
        ctx->log_to_file = false;
        return -1;
    }

    snprintf(ctx->log_file, sizeof(ctx->log_file), "%s", log_file);
    ctx->log_to_file = true;
    return 0;
}

void logger_close(firewall_ctx_t *ctx) {
    if (ctx->log_fp) {
        fclose(ctx->log_fp);
        ctx->log_fp = NULL;
    }
    ctx->log_to_file = false;
}

void logger_write(firewall_ctx_t *ctx, log_entry_t *entry) {
    if (!ctx->log_fp || !entry) return;

    fprintf(ctx->log_fp, "%ld|%s|%s|%s|%s|%s|%d|%d|%s|%s\n",
            (long)entry->timestamp, action_to_string(entry->action),
            entry->src_mac, entry->dst_mac,
            entry->src_ip, entry->dst_ip,
            entry->src_port, entry->dst_port,
            entry->protocol, entry->reason);
    fflush(ctx->log_fp);
}
