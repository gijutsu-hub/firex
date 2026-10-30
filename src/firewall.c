#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "firewall.h"
#include "dpi.h"
#include "ratelimit.h"
#include "logger.h"

// ========== HELPERS ==========
void mac_to_string(unsigned char *mac, char *str) {
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void string_to_mac(const char *str, unsigned char *mac) {
    memset(mac, 0, 6);
    sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

const char *action_to_string(fw_action_t action) {
    switch (action) {
        case ACTION_ALLOW:      return "ALLOW";
        case ACTION_BLOCK:      return "BLOCK";
        case ACTION_LOG_ONLY:   return "LOG";
        case ACTION_RATE_LIMIT: return "RATE_LIMIT";
        default:                return "UNKNOWN";
    }
}

const char *protocol_to_string(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "OTHER";
    }
}

const char *rule_type_to_string(rule_type_t type) {
    switch (type) {
        case RULE_MAC_SRC:      return "MAC_SRC";
        case RULE_MAC_DST:      return "MAC_DST";
        case RULE_IP_SRC:       return "IP_SRC";
        case RULE_IP_DST:       return "IP_DST";
        case RULE_IP_RANGE:     return "IP_RANGE";
        case RULE_PORT_SRC:     return "PORT_SRC";
        case RULE_PORT_DST:     return "PORT_DST";
        case RULE_PORT_RANGE:   return "PORT_RANGE";
        case RULE_PROTOCOL:     return "PROTOCOL";
        case RULE_ETHERTYPE:    return "ETHERTYPE";
        case RULE_DPI_REGEX:    return "DPI_REGEX";
        case RULE_DPI_CONTENT:  return "DPI_CONTENT";
        case RULE_RATE_LIMIT:   return "RATE_LIMIT";
        default:                return "UNKNOWN";
    }
}

// ========== CREATE/DESTROY ==========
firewall_ctx_t *fw_create(void) {
    firewall_ctx_t *ctx = calloc(1, sizeof(firewall_ctx_t));
    if (!ctx) return NULL;

    pthread_mutex_init(&ctx->rules_lock, NULL);
    pthread_mutex_init(&ctx->log_lock, NULL);
    pthread_mutex_init(&ctx->stats_lock, NULL);
    rate_limiter_init(&ctx->rate_limiter);

    ctx->default_policy = ACTION_ALLOW;
    ctx->engine = ENGINE_RAW_SOCKET;
    ctx->sockfd = -1;
    ctx->queue_num = 0;
    ctx->stats.start_time = time(NULL);

    return ctx;
}

void fw_destroy(firewall_ctx_t *ctx) {
    if (!ctx) return;

    fw_stop(ctx);

    // Free compiled regex patterns
    for (int i = 0; i < ctx->rule_count; i++) {
        if (ctx->rules[i].regex_compiled)
            dpi_free_regex(&ctx->rules[i]);
    }

    rate_limiter_cleanup(&ctx->rate_limiter);
    logger_close(ctx);

    pthread_mutex_destroy(&ctx->rules_lock);
    pthread_mutex_destroy(&ctx->log_lock);
    pthread_mutex_destroy(&ctx->stats_lock);

    free(ctx);
}

// ========== PARSE PACKET ==========
void parse_packet(unsigned char *buffer, int len, packet_info_t *pkt) {
    memset(pkt, 0, sizeof(*pkt));
    if (len < 14) return;

    pkt->total_len = len;
    pkt->timestamp = time(NULL);
    memcpy(pkt->dst_mac, buffer, 6);
    memcpy(pkt->src_mac, buffer + 6, 6);

    int offset = 12;
    uint16_t ethertype;
    memcpy(&ethertype, buffer + offset, 2);
    ethertype = ntohs(ethertype);
    offset += 2;

    /* Unwrap an outer QinQ service tag, then a customer tag. Untagged frames
     * leave vlan_id at 0; the segmentation layer fills in the port's PVID. */
    if (ethertype == 0x88A8 && len >= offset + 4) {
        uint16_t tci;
        memcpy(&tci, buffer + offset, 2);
        tci = ntohs(tci);
        pkt->outer_vlan = tci & 0x0FFF;
        pkt->vlan_pcp   = (tci >> 13) & 0x7;
        memcpy(&ethertype, buffer + offset + 2, 2);
        ethertype = ntohs(ethertype);
        offset += 4;
    }

    if (ethertype == 0x8100 && len >= offset + 4) {
        uint16_t tci;
        memcpy(&tci, buffer + offset, 2);
        tci = ntohs(tci);
        pkt->vlan_id   = tci & 0x0FFF;
        pkt->vlan_pcp  = (tci >> 13) & 0x7;
        pkt->vlan_dei  = (tci & 0x1000) ? 1 : 0;
        pkt->is_tagged = true;
        memcpy(&ethertype, buffer + offset + 2, 2);
        ethertype = ntohs(ethertype);
        offset += 4;
    }

    pkt->ethertype = ethertype;

    if (ethertype == ETH_P_IP && len >= offset + 20) {
        struct iphdr *ip = (struct iphdr*)(buffer + offset);
        int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < 20 || offset + ip_hdr_len > len) return;

        pkt->src_ip = ip->saddr;
        pkt->dst_ip = ip->daddr;
        pkt->protocol = ip->protocol;
        pkt->ttl = ip->ttl;
        pkt->has_ip = true;

        int transport_offset = offset + ip_hdr_len;

        if (pkt->protocol == IPPROTO_TCP && len >= transport_offset + 20) {
            struct tcphdr *tcp = (struct tcphdr*)(buffer + transport_offset);
            pkt->src_port = ntohs(tcp->source);
            pkt->dst_port = ntohs(tcp->dest);
            pkt->tcp_flags = ((unsigned char*)(buffer + transport_offset))[13];
            pkt->tcp_seq = ntohl(tcp->seq);
            pkt->tcp_ack = ntohl(tcp->ack_seq);

            int tcp_hdr_len = tcp->doff * 4;
            if (tcp_hdr_len < 20) return;
            int payload_offset = transport_offset + tcp_hdr_len;
            if (len > payload_offset) {
                pkt->payload = buffer + payload_offset;
                pkt->payload_len = len - payload_offset;
            }
        } else if (pkt->protocol == IPPROTO_UDP && len >= transport_offset + 8) {
            struct udphdr *udp = (struct udphdr*)(buffer + transport_offset);
            pkt->src_port = ntohs(udp->source);
            pkt->dst_port = ntohs(udp->dest);

            int payload_offset = transport_offset + 8;
            if (len > payload_offset) {
                pkt->payload = buffer + payload_offset;
                pkt->payload_len = len - payload_offset;
            }
        }
    }
}

void fw_set_inspect_hook(firewall_ctx_t *ctx, fw_inspect_hook_t hook) {
    if (ctx) ctx->inspect_hook = hook;
}

// ========== RULE CHECK ENGINE ==========
static bool match_rule(firewall_ctx_t *ctx, fw_rule_t *rule, packet_info_t *pkt) {
    if (!rule->enabled) return false;

    switch (rule->type) {
        case RULE_MAC_SRC:
            return memcmp(pkt->src_mac, rule->mac, 6) == 0;

        case RULE_MAC_DST:
            return memcmp(pkt->dst_mac, rule->mac, 6) == 0;

        case RULE_IP_SRC:
            if (!pkt->has_ip) return false;
            if (rule->ip_mask)
                return (pkt->src_ip & rule->ip_mask) == (rule->ip & rule->ip_mask);
            return pkt->src_ip == rule->ip;

        case RULE_IP_DST:
            if (!pkt->has_ip) return false;
            if (rule->ip_mask)
                return (pkt->dst_ip & rule->ip_mask) == (rule->ip & rule->ip_mask);
            return pkt->dst_ip == rule->ip;

        case RULE_IP_RANGE:
            if (!pkt->has_ip) return false;
            return (ntohl(pkt->src_ip) >= ntohl(rule->ip) &&
                    ntohl(pkt->src_ip) <= ntohl(rule->ip_end));

        case RULE_PORT_SRC:
            if (!pkt->has_ip) return false;
            return pkt->src_port == rule->port;

        case RULE_PORT_DST:
            if (!pkt->has_ip) return false;
            return pkt->dst_port == rule->port;

        case RULE_PORT_RANGE:
            if (!pkt->has_ip) return false;
            return (pkt->dst_port >= rule->port && pkt->dst_port <= rule->port_end) ||
                   (pkt->src_port >= rule->port && pkt->src_port <= rule->port_end);

        case RULE_PROTOCOL:
            if (!pkt->has_ip) return false;
            return pkt->protocol == rule->protocol;

        case RULE_ETHERTYPE:
            return pkt->ethertype == rule->ethertype;

        case RULE_DPI_REGEX:
            return dpi_match_regex(rule, pkt);

        case RULE_DPI_CONTENT:
            return dpi_match_content(rule, pkt);

        case RULE_RATE_LIMIT:
            if (!pkt->has_ip) return false;
            return !rate_limiter_check(&ctx->rate_limiter, pkt->src_ip,
                                       pkt->total_len,
                                       rule->max_packets_per_sec,
                                       rule->max_bytes_per_sec);
        default:
            return false;
    }
}

fw_action_t fw_check_packet(firewall_ctx_t *ctx, packet_info_t *pkt, int *matched_rule) {
    pthread_mutex_lock(&ctx->rules_lock);

    // Rules are kept sorted by priority (lower number = higher priority),
    // so the first match wins.
    for (int i = 0; i < ctx->rule_count; i++) {
        if (match_rule(ctx, &ctx->rules[i], pkt)) {
            ctx->rules[i].hit_count++;
            *matched_rule = ctx->rules[i].id;
            fw_action_t action = ctx->rules[i].action;
            bool dpi = (ctx->rules[i].type == RULE_DPI_REGEX ||
                        ctx->rules[i].type == RULE_DPI_CONTENT);
            pthread_mutex_unlock(&ctx->rules_lock);

            if (dpi) {
                pthread_mutex_lock(&ctx->stats_lock);
                ctx->stats.dpi_matches++;
                pthread_mutex_unlock(&ctx->stats_lock);
            }
            return action;
        }
    }

    pthread_mutex_unlock(&ctx->rules_lock);
    *matched_rule = -1;
    return ctx->default_policy;
}

// ========== RULE MANAGEMENT ==========
int fw_add_rule(firewall_ctx_t *ctx, fw_rule_t *rule) {
    pthread_mutex_lock(&ctx->rules_lock);
    if (ctx->rule_count >= MAX_RULES) {
        pthread_mutex_unlock(&ctx->rules_lock);
        return -1;
    }

    rule->id = ctx->next_rule_id++;
    rule->created = time(NULL);
    rule->hit_count = 0;

    // Compile regex if DPI rule
    rule->regex_compiled = false;
    if (rule->type == RULE_DPI_REGEX && strlen(rule->regex_pattern) > 0) {
        if (dpi_compile_regex(rule) != 0) {
            pthread_mutex_unlock(&ctx->rules_lock);
            return -1;  // bad pattern: reject rather than silently never match
        }
    }

    memcpy(&ctx->rules[ctx->rule_count], rule, sizeof(fw_rule_t));
    ctx->rule_count++;

    // Keep the table ordered by priority. Insertion sort over the tail keeps
    // the compiled regex_t values in their own slots (no aliasing copies).
    for (int i = ctx->rule_count - 1; i > 0; i--) {
        if (ctx->rules[i].priority < ctx->rules[i - 1].priority) {
            fw_rule_t tmp = ctx->rules[i];
            ctx->rules[i] = ctx->rules[i - 1];
            ctx->rules[i - 1] = tmp;
        } else {
            break;
        }
    }

    int id = rule->id;
    ctx->rules_generation++;
    pthread_mutex_unlock(&ctx->rules_lock);
    return id;
}

int fw_remove_rule(firewall_ctx_t *ctx, int rule_id) {
    pthread_mutex_lock(&ctx->rules_lock);
    for (int i = 0; i < ctx->rule_count; i++) {
        if (ctx->rules[i].id == rule_id) {
            if (ctx->rules[i].regex_compiled)
                dpi_free_regex(&ctx->rules[i]);
            memmove(&ctx->rules[i], &ctx->rules[i + 1],
                    (ctx->rule_count - i - 1) * sizeof(fw_rule_t));
            ctx->rule_count--;
            ctx->rules_generation++;
            pthread_mutex_unlock(&ctx->rules_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->rules_lock);
    return -1;
}

int fw_toggle_rule(firewall_ctx_t *ctx, int rule_id, bool enabled) {
    pthread_mutex_lock(&ctx->rules_lock);
    for (int i = 0; i < ctx->rule_count; i++) {
        if (ctx->rules[i].id == rule_id) {
            ctx->rules[i].enabled = enabled;
            ctx->rules_generation++;
            pthread_mutex_unlock(&ctx->rules_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->rules_lock);
    return -1;
}

void fw_clear_rules(firewall_ctx_t *ctx) {
    pthread_mutex_lock(&ctx->rules_lock);
    for (int i = 0; i < ctx->rule_count; i++) {
        if (ctx->rules[i].regex_compiled)
            dpi_free_regex(&ctx->rules[i]);
    }
    ctx->rule_count = 0;
    ctx->rules_generation++;
    pthread_mutex_unlock(&ctx->rules_lock);
}

// ========== LOGGING ==========
void fw_log(firewall_ctx_t *ctx, packet_info_t *pkt, fw_action_t action, int rule_id) {
    pthread_mutex_lock(&ctx->log_lock);

    int idx = ctx->log_index % MAX_LOG_ENTRIES;
    log_entry_t *entry = &ctx->logs[idx];
    memset(entry, 0, sizeof(*entry));

    entry->timestamp = pkt->timestamp;
    entry->action = action;
    entry->rule_id = rule_id;
    entry->packet_size = pkt->total_len;

    mac_to_string(pkt->src_mac, entry->src_mac);
    mac_to_string(pkt->dst_mac, entry->dst_mac);

    if (pkt->has_ip) {
        struct in_addr s = {pkt->src_ip}, d = {pkt->dst_ip};
        inet_ntop(AF_INET, &s, entry->src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &d, entry->dst_ip, INET_ADDRSTRLEN);
    } else {
        strcpy(entry->src_ip, "-");
        strcpy(entry->dst_ip, "-");
    }

    entry->src_port = pkt->src_port;
    entry->dst_port = pkt->dst_port;
    snprintf(entry->protocol, sizeof(entry->protocol), "%s",
             pkt->has_ip ? protocol_to_string(pkt->protocol)
                         : (pkt->ethertype == ETH_P_ARP ? "ARP" : "L2"));

    // Find rule description
    if (rule_id < 0) {
        snprintf(entry->reason, sizeof(entry->reason), "Default Policy");
    } else {
        snprintf(entry->reason, sizeof(entry->reason), "Rule #%d", rule_id);
        pthread_mutex_lock(&ctx->rules_lock);
        for (int i = 0; i < ctx->rule_count; i++) {
            if (ctx->rules[i].id == rule_id) {
                const char *desc = ctx->rules[i].description;
                if (desc[0]) {
                    // Plain copy: both buffers live inside ctx, and snprintf's
                    // restrict-qualified arguments make GCC assume they overlap.
                    size_t n = strnlen(desc, sizeof(entry->reason) - 1);
                    memcpy(entry->reason, desc, n);
                    entry->reason[n] = '\0';
                }
                break;
            }
        }
        pthread_mutex_unlock(&ctx->rules_lock);
    }

    ctx->log_index++;
    if (ctx->log_count < MAX_LOG_ENTRIES)
        ctx->log_count++;

    // Write to file if enabled
    if (ctx->log_fp) {
        fprintf(ctx->log_fp, "%ld|%s|%s|%s|%s|%s|%d|%d|%s|%s\n",
                (long)entry->timestamp, action_to_string(action),
                entry->src_mac, entry->dst_mac,
                entry->src_ip, entry->dst_ip,
                entry->src_port, entry->dst_port,
                entry->protocol, entry->reason);
        fflush(ctx->log_fp);
    }

    pthread_mutex_unlock(&ctx->log_lock);
}

log_entry_t *fw_get_logs(firewall_ctx_t *ctx, int *count) {
    pthread_mutex_lock(&ctx->log_lock);
    if (count) *count = ctx->log_count;
    pthread_mutex_unlock(&ctx->log_lock);
    return ctx->logs;
}

// ========== STATISTICS ==========
void update_stats(firewall_ctx_t *ctx, packet_info_t *pkt, fw_action_t action) {
    pthread_mutex_lock(&ctx->stats_lock);

    ctx->stats.total_packets++;
    ctx->stats.total_bytes += pkt->total_len;

    switch (action) {
        case ACTION_ALLOW:      ctx->stats.allowed++; break;
        case ACTION_BLOCK:      ctx->stats.blocked++; break;
        case ACTION_LOG_ONLY:   ctx->stats.logged++; break;
        case ACTION_RATE_LIMIT: ctx->stats.rate_limited++; break;
    }

    if (pkt->has_ip) {
        switch (pkt->protocol) {
            case IPPROTO_TCP:  ctx->stats.tcp_count++; break;
            case IPPROTO_UDP:  ctx->stats.udp_count++; break;
            case IPPROTO_ICMP: ctx->stats.icmp_count++; break;
            default:           ctx->stats.other_count++; break;
        }
    } else if (pkt->ethertype != ETH_P_ARP) {
        ctx->stats.other_count++;
    }
    if (pkt->ethertype == ETH_P_ARP) ctx->stats.arp_count++;

    time_t now = time(NULL);
    time_t elapsed = now - ctx->stats.start_time;
    if (elapsed > 0) {
        ctx->stats.packets_per_second = (double)ctx->stats.total_packets / elapsed;
        ctx->stats.bytes_per_second = (double)ctx->stats.total_bytes / elapsed;
    }
    ctx->stats.last_update = now;

    pthread_mutex_unlock(&ctx->stats_lock);
}

fw_stats_t fw_get_stats(firewall_ctx_t *ctx) {
    pthread_mutex_lock(&ctx->stats_lock);
    fw_stats_t s = ctx->stats;
    pthread_mutex_unlock(&ctx->stats_lock);
    return s;
}

void fw_reset_stats(firewall_ctx_t *ctx) {
    pthread_mutex_lock(&ctx->stats_lock);
    memset(&ctx->stats, 0, sizeof(fw_stats_t));
    ctx->stats.start_time = time(NULL);
    pthread_mutex_unlock(&ctx->stats_lock);
}

// ========== RAW SOCKET CAPTURE ==========
static void *raw_capture_thread(void *arg) {
    firewall_ctx_t *ctx = (firewall_ctx_t *)arg;
    unsigned char buffer[65536];

    while (ctx->running) {
        int len = recvfrom(ctx->sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            if (!ctx->running) break;
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            break;
        }

        packet_info_t pkt;
        parse_packet(buffer, len, &pkt);
        snprintf(pkt.ingress_if, MAX_IFACE_NAME, "%s", ctx->interface);

        int matched_rule = -1;
        fw_action_t action = ctx->inspect_hook
            ? ctx->inspect_hook(ctx, &pkt, ctx->interface, &matched_rule)
            : fw_check_packet(ctx, &pkt, &matched_rule);

        update_stats(ctx, &pkt, action);
        fw_log(ctx, &pkt, action, matched_rule);
    }
    return NULL;
}

// ========== START/STOP ==========
int fw_start(firewall_ctx_t *ctx, const char *iface, engine_t engine) {
    snprintf(ctx->interface, MAX_IFACE_NAME, "%s", iface);
    ctx->engine = engine;

    if (engine == ENGINE_RAW_SOCKET) {
        ctx->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (ctx->sockfd < 0) {
            perror("socket");
            return -1;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);
        if (ioctl(ctx->sockfd, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl(SIOCGIFINDEX)");
            close(ctx->sockfd);
            ctx->sockfd = -1;
            return -1;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(ctx->sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind");
            close(ctx->sockfd);
            ctx->sockfd = -1;
            return -1;
        }

        // Wake the capture thread periodically so a stop request is noticed
        // even on a silent link.
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        ctx->running = true;
        if (pthread_create(&ctx->capture_thread, NULL, raw_capture_thread, ctx) != 0) {
            perror("pthread_create");
            ctx->running = false;
            close(ctx->sockfd);
            ctx->sockfd = -1;
            return -1;
        }
        ctx->capture_thread_valid = true;
        return 0;
    }

    return -1;  // other engines have their own start functions
}

void fw_stop(firewall_ctx_t *ctx) {
    if (!ctx) return;
    ctx->running = false;

    if (ctx->sockfd >= 0) {
        shutdown(ctx->sockfd, SHUT_RDWR);
        close(ctx->sockfd);
        ctx->sockfd = -1;
    }
    if (ctx->capture_thread_valid) {
        pthread_join(ctx->capture_thread, NULL);
        ctx->capture_thread_valid = false;
    }
}
