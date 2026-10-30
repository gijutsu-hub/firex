#ifndef FW_LOGGER_H
#define FW_LOGGER_H

#include "firewall.h"

int logger_init(firewall_ctx_t *ctx, const char *log_file);
void logger_close(firewall_ctx_t *ctx);
void logger_write(firewall_ctx_t *ctx, log_entry_t *entry);
int logger_export_csv(firewall_ctx_t *ctx, const char *filename);

#endif
