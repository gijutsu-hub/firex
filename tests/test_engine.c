/*
 * Rule-engine tests. No root, no network: builds synthetic Ethernet frames and
 * runs them through the same parse/match path the capture engines use.
 *   make test
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include "firewall.h"

static int pass = 0, fail = 0;

// Build an Ethernet + IPv4 (+ TCP) frame into buf, return its length.
static int build_frame(unsigned char *buf, const char *src_ip, const char *dst_ip,
                       uint8_t proto, uint16_t sport, uint16_t dport,
                       const char *payload) {
    memset(buf, 0, 1600);
    unsigned char smac[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    unsigned char dmac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    memcpy(buf, dmac, 6);
    memcpy(buf + 6, smac, 6);
    uint16_t et = htons(ETH_P_IP);
    memcpy(buf + 12, &et, 2);

    struct iphdr *ip = (struct iphdr *)(buf + 14);
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = proto;
    inet_pton(AF_INET, src_ip, &ip->saddr);
    inet_pton(AF_INET, dst_ip, &ip->daddr);

    int len = 14 + 20;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(buf + 34);
        tcp->source = htons(sport);
        tcp->dest = htons(dport);
        tcp->doff = 5;
        len += 20;
        if (payload) {
            int plen = (int)strlen(payload);
            memcpy(buf + len, payload, plen);
            len += plen;
        }
    } else {
        len += 8;  // room for an ICMP header
    }
    ip->tot_len = htons(len - 14);
    return len;
}

static void check(firewall_ctx_t *ctx, const char *name, unsigned char *buf,
                  int len, fw_action_t expect) {
    packet_info_t pkt;
    parse_packet(buf, len, &pkt);
    int rule = -1;
    fw_action_t got = fw_check_packet(ctx, &pkt, &rule);

    if (got == expect) {
        printf("  PASS  %-38s -> %-10s (rule %d)\n", name, action_to_string(got), rule);
        pass++;
    } else {
        printf("  FAIL  %-38s -> %s, expected %s\n", name,
               action_to_string(got), action_to_string(expect));
        fail++;
    }
}

int main(void) {
    firewall_ctx_t *ctx = fw_create();
    if (!ctx) { puts("fw_create failed"); return 1; }

    if (fw_load_config(ctx, "config/rules.conf") != 0) {
        puts("could not load config/rules.conf"); return 1;
    }
    printf("Loaded %d rules, default policy %s\n\n",
           ctx->rule_count, action_to_string(ctx->default_policy));

    printf("Rule order (by priority):\n");
    for (int i = 0; i < ctx->rule_count; i++)
        printf("  [%d] prio=%-4d %-12s %-10s %s\n", ctx->rules[i].id,
               ctx->rules[i].priority, rule_type_to_string(ctx->rules[i].type),
               action_to_string(ctx->rules[i].action), ctx->rules[i].description);

    puts("\nPacket verdicts:");
    unsigned char buf[1600];
    int len;

    len = build_frame(buf, "10.0.0.5", "10.0.0.1", IPPROTO_ICMP, 0, 0, NULL);
    check(ctx, "ICMP ping", buf, len, ACTION_BLOCK);

    len = build_frame(buf, "10.0.0.5", "10.0.0.1", IPPROTO_TCP, 50000, 23, NULL);
    check(ctx, "TCP -> port 23 (telnet)", buf, len, ACTION_BLOCK);

    len = build_frame(buf, "10.0.0.5", "10.0.0.1", IPPROTO_TCP, 50001, 21, NULL);
    check(ctx, "TCP -> port 21 (ftp)", buf, len, ACTION_BLOCK);

    len = build_frame(buf, "10.0.0.5", "10.0.0.1", IPPROTO_TCP, 50002, 443, NULL);
    check(ctx, "TCP -> port 443 (default allow)", buf, len, ACTION_ALLOW);

    len = build_frame(buf, "10.0.0.5", "10.0.0.1", IPPROTO_TCP, 50003, 8080,
                      "GET /x?q=1 UNION SELECT pw FROM users HTTP/1.1\r\n");
    check(ctx, "DPI: SQL injection in payload", buf, len, ACTION_BLOCK);

    len = build_frame(buf, "10.0.0.5", "10.0.0.1", IPPROTO_TCP, 50004, 8080,
                      "POST / HTTP/1.1\r\n\r\n<script>alert(1)</script>");
    check(ctx, "DPI: XSS in payload", buf, len, ACTION_BLOCK);

    len = build_frame(buf, "10.0.0.5", "10.0.0.1", IPPROTO_TCP, 50005, 8080,
                      "POST / HTTP/1.1\r\n\r\nhello world");
    check(ctx, "DPI: benign payload", buf, len, ACTION_ALLOW);

    // A rule added through the API, as the GUI would
    fw_rule_t r;
    memset(&r, 0, sizeof(r));
    r.type = RULE_IP_SRC; r.action = ACTION_BLOCK; r.priority = 1;
    r.enabled = true;
    inet_pton(AF_INET, "192.168.9.9", &r.ip);
    snprintf(r.description, MAX_DESC_LEN, "Block a specific host");
    int id = fw_add_rule(ctx, &r);
    printf("\n  added rule id=%d\n", id);

    len = build_frame(buf, "192.168.9.9", "10.0.0.1", IPPROTO_TCP, 1234, 443, NULL);
    check(ctx, "blocked source IP", buf, len, ACTION_BLOCK);

    fw_toggle_rule(ctx, id, false);
    check(ctx, "same packet, rule disabled", buf, len, ACTION_ALLOW);

    fw_remove_rule(ctx, id);
    check(ctx, "same packet, rule removed", buf, len, ACTION_ALLOW);

    // Save/load round trip
    int before = ctx->rule_count;
    if (fw_save_config(ctx, "build/fw_roundtrip.conf") != 0) { puts("save failed"); fail++; }
    if (fw_load_config(ctx, "build/fw_roundtrip.conf") != 0) { puts("load failed"); fail++; }
    if (ctx->rule_count == before) {
        printf("  PASS  %-38s -> %d rules\n", "config save/load round trip", before);
        pass++;
    } else {
        printf("  FAIL  save/load: %d rules before, %d after\n", before, ctx->rule_count);
        fail++;
    }

    // A bad regex must be rejected, not stored as a rule that never matches
    memset(&r, 0, sizeof(r));
    r.type = RULE_DPI_REGEX; r.action = ACTION_BLOCK; r.enabled = true;
    snprintf(r.regex_pattern, MAX_REGEX_LEN, "%s", "([unclosed");
    if (fw_add_rule(ctx, &r) < 0) {
        printf("  PASS  %-38s -> rejected\n", "invalid regex"); pass++;
    } else {
        printf("  FAIL  invalid regex was accepted\n"); fail++;
    }

    // Truncated / malformed frames must not crash the parser
    unsigned char tiny[8] = {0};
    packet_info_t p;
    parse_packet(tiny, 8, &p);
    buf[14] = 0x40;  // version 4, ihl 0 -> header length below the minimum
    parse_packet(buf, len, &p);
    printf("  PASS  %-38s -> no crash\n", "malformed/truncated frames"); pass++;

    fw_destroy(ctx);
    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
