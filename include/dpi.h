#ifndef FW_DPI_H
#define FW_DPI_H

#include "firewall.h"

int dpi_compile_regex(fw_rule_t *rule);
int dpi_match_content(fw_rule_t *rule, packet_info_t *pkt);
int dpi_match_regex(fw_rule_t *rule, packet_info_t *pkt);
void dpi_free_regex(fw_rule_t *rule);

// Predefined DPI patterns
const char *dpi_get_http_pattern(void);
const char *dpi_get_ssh_pattern(void);
const char *dpi_get_dns_pattern(void);
const char *dpi_get_malware_pattern(void);

#endif
