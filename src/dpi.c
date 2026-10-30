#include <string.h>
#include <regex.h>
#include "dpi.h"

int dpi_compile_regex(fw_rule_t *rule) {
    if (rule->regex_compiled) dpi_free_regex(rule);
    int ret = regcomp(&rule->compiled_regex, rule->regex_pattern,
                      REG_EXTENDED | REG_NOSUB | REG_ICASE);
    rule->regex_compiled = (ret == 0);
    return ret;
}

int dpi_match_regex(fw_rule_t *rule, packet_info_t *pkt) {
    if (!rule->regex_compiled || !pkt->payload || pkt->payload_len <= 0)
        return 0;

    // Create null-terminated copy for regex
    char buf[MAX_PAYLOAD_LEN + 1];
    int copy_len = pkt->payload_len < MAX_PAYLOAD_LEN ? pkt->payload_len : MAX_PAYLOAD_LEN;
    memcpy(buf, pkt->payload, copy_len);
    buf[copy_len] = '\0';

    return regexec(&rule->compiled_regex, buf, 0, NULL, 0) == 0;
}

int dpi_match_content(fw_rule_t *rule, packet_info_t *pkt) {
    if (!pkt->payload || pkt->payload_len <= 0 || rule->content_len <= 0)
        return 0;
    if (rule->content_len > pkt->payload_len)
        return 0;

    for (int i = 0; i <= pkt->payload_len - rule->content_len; i++) {
        if (memcmp(pkt->payload + i, rule->content_match, rule->content_len) == 0)
            return 1;
    }
    return 0;
}

void dpi_free_regex(fw_rule_t *rule) {
    if (rule->regex_compiled) {
        regfree(&rule->compiled_regex);
        rule->regex_compiled = false;
    }
}

const char *dpi_get_http_pattern(void) {
    return "(GET|POST|PUT|DELETE|HEAD|OPTIONS)[[:space:]]+/";
}

const char *dpi_get_ssh_pattern(void) {
    return "^SSH-[0-9]";
}

const char *dpi_get_dns_pattern(void) {
    return ".*";  // DNS needs port-based detection mainly
}

const char *dpi_get_malware_pattern(void) {
    return "(eval\\(|<script|cmd\\.exe|/bin/sh|SELECT.*FROM|UNION.*SELECT)";
}
