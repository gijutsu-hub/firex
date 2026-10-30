#ifndef FLAMEWALL_H
#define FLAMEWALL_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <regex.h>
#include <time.h>
#include <netinet/in.h>
#include "zone.h"

// ========== VERSION ==========
#define FW_VERSION "1.0.0"
#define FW_NAME "FlameWall"

// ========== LIMITS ==========
#define MAX_RULES       500
#define MAX_LOG_ENTRIES 10000
#define MAX_IFACE_NAME  32
#define MAX_REGEX_LEN   256
#define MAX_DESC_LEN    128
#define MAX_PAYLOAD_LEN 1500
#define RATE_LIMIT_WINDOW 60 // seconds

// ========== ENUMS ==========
typedef enum {
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_LOG_ONLY,
    ACTION_RATE_LIMIT
} fw_action_t;

typedef enum {
    RULE_MAC_SRC,
    RULE_MAC_DST,
    RULE_IP_SRC,
    RULE_IP_DST,
    RULE_IP_RANGE,
    RULE_PORT_SRC,
    RULE_PORT_DST,
    RULE_PORT_RANGE,
    RULE_PROTOCOL,
    RULE_ETHERTYPE,
    RULE_DPI_REGEX,       // Deep Packet Inspection
    RULE_DPI_CONTENT,     // Content string match
    RULE_RATE_LIMIT,      // Rate limiting
    RULE_COUNTRY,         // GeoIP (future)
} rule_type_t;

typedef enum {
    PROTO_ANY = 0,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMP = 1,
    PROTO_ARP = 200  // pseudo
} protocol_t;

typedef enum {
    DIR_INBOUND,
    DIR_OUTBOUND,
    DIR_BOTH
} direction_t;

typedef enum {
    ENGINE_RAW_SOCKET,
    ENGINE_NFQUEUE,
    ENGINE_XDP
} engine_t;

// ========== RULE STRUCTURE ==========
typedef struct {
    int id;
    bool enabled;
    rule_type_t type;
    fw_action_t action;
    direction_t direction;
    int priority;        // Lower = higher priority

    // MAC
    unsigned char mac[6];
    bool mac_set;

    // IP
    uint32_t ip;
    uint32_t ip_mask;    // For CIDR ranges
    uint32_t ip_end;     // For ranges

    // Ports
    uint16_t port;
    uint16_t port_end;   // For ranges

    // Protocol
    uint8_t protocol;

    // EtherType
    uint16_t ethertype;

    // DPI
    char regex_pattern[MAX_REGEX_LEN];
    regex_t compiled_regex;
    bool regex_compiled;
    char content_match[MAX_PAYLOAD_LEN];
    int content_len;

    // Rate limiting
    int max_packets_per_sec;
    int max_bytes_per_sec;

    // Metadata
    char description[MAX_DESC_LEN];
    time_t created;
    unsigned long hit_count;
} fw_rule_t;

// ========== PACKET INFO ==========
typedef struct {
    // Layer 2
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    uint16_t ethertype;

    // Layer 3
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t protocol;
    uint8_t ttl;
    bool has_ip;

    // Layer 4
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;

    // Payload
    unsigned char *payload;
    int payload_len;

    // TCP sequence state (needed to forge a block-page redirect)
    uint32_t tcp_seq;
    uint32_t tcp_ack;

    // VLAN / segmentation context
    uint16_t vlan_id;          // resolved tag, or the ingress port's PVID
    uint16_t outer_vlan;       // QinQ service tag, 0 when absent
    uint8_t  vlan_pcp;
    uint8_t  vlan_dei;
    bool     is_tagged;
    bool     vlan_violation;   // tag not permitted on the ingress port
    zone_t   zone;
    char     ingress_if[MAX_IFACE_NAME];

    // Meta
    int total_len;
    time_t timestamp;
    direction_t direction;
} packet_info_t;

/* Optional inspection hook. When set, the capture engines call this instead
 * of fw_check_packet() alone, letting the segmentation / block-page layer add
 * its own verdicts. Leaving it NULL keeps plain rule matching.
 *
 * Declared before firewall_ctx_t because the context stores one. */
typedef struct firewall_ctx firewall_ctx_t;
typedef fw_action_t (*fw_inspect_hook_t)(firewall_ctx_t *ctx,
                                         packet_info_t *pkt,
                                         const char *ingress_if,
                                         int *rule_id);

// ========== LOG ENTRY ==========
typedef struct {
    time_t timestamp;
    fw_action_t action;
    char src_mac[18];
    char dst_mac[18];
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    char protocol[8];
    char reason[MAX_DESC_LEN];
    int packet_size;
    int rule_id;
} log_entry_t;

// ========== STATISTICS ==========
typedef struct {
    unsigned long total_packets;
    unsigned long total_bytes;
    unsigned long allowed;
    unsigned long blocked;
    unsigned long logged;
    unsigned long rate_limited;

    unsigned long tcp_count;
    unsigned long udp_count;
    unsigned long icmp_count;
    unsigned long arp_count;
    unsigned long other_count;

    unsigned long dpi_matches;
    double packets_per_second;
    double bytes_per_second;

    time_t start_time;
    time_t last_update;
} fw_stats_t;

// ========== RATE LIMITER ==========
typedef struct {
    uint32_t ip;
    int packet_count;
    int byte_count;
    time_t window_start;
} rate_entry_t;

#define MAX_RATE_ENTRIES 10000

typedef struct {
    rate_entry_t entries[MAX_RATE_ENTRIES];
    int count;
    pthread_mutex_t lock;
} rate_limiter_t;

// ========== FIREWALL CONTEXT ==========
struct firewall_ctx {
    // Rules
    fw_rule_t rules[MAX_RULES];
    int rule_count;
    int next_rule_id;
    /* Bumped on every rule change so an offload backend (XDP) can notice
     * edits made in the GUI and re-sync its maps. Read under rules_lock. */
    unsigned rules_generation;
    pthread_mutex_t rules_lock;

    // Logs
    log_entry_t logs[MAX_LOG_ENTRIES];
    int log_count;
    int log_index; // circular
    pthread_mutex_t log_lock;

    // Statistics
    fw_stats_t stats;
    pthread_mutex_t stats_lock;

    // Rate limiter
    rate_limiter_t rate_limiter;

    // Engine
    engine_t engine;
    int sockfd;
    bool running;
    char interface[MAX_IFACE_NAME];
    int queue_num;

    // Threads
    pthread_t capture_thread;
    bool capture_thread_valid;
    pthread_t stats_thread;

    // Config
    char config_file[256];
    bool log_to_file;
    char log_file[256];
    FILE *log_fp;

    // Default policy
    fw_action_t default_policy;

    // Enterprise inspection hook (NULL = plain rule matching)
    fw_inspect_hook_t inspect_hook;
};

// ========== CORE FUNCTIONS ==========
firewall_ctx_t *fw_create(void);
void fw_destroy(firewall_ctx_t *ctx);
int fw_start(firewall_ctx_t *ctx, const char *iface, engine_t engine);
void fw_stop(firewall_ctx_t *ctx);

// Rules
int fw_add_rule(firewall_ctx_t *ctx, fw_rule_t *rule);
int fw_remove_rule(firewall_ctx_t *ctx, int rule_id);
int fw_toggle_rule(firewall_ctx_t *ctx, int rule_id, bool enabled);
fw_action_t fw_check_packet(firewall_ctx_t *ctx, packet_info_t *pkt, int *matched_rule);
void fw_clear_rules(firewall_ctx_t *ctx);

// Packet plumbing (shared by the capture engines)
void parse_packet(unsigned char *buffer, int len, packet_info_t *pkt);
void fw_set_inspect_hook(firewall_ctx_t *ctx, fw_inspect_hook_t hook);
void update_stats(firewall_ctx_t *ctx, packet_info_t *pkt, fw_action_t action);

// Config
int fw_save_config(firewall_ctx_t *ctx, const char *filename);
int fw_load_config(firewall_ctx_t *ctx, const char *filename);

// Logging
void fw_log(firewall_ctx_t *ctx, packet_info_t *pkt, fw_action_t action, int rule_id);
log_entry_t *fw_get_logs(firewall_ctx_t *ctx, int *count);

// Stats
fw_stats_t fw_get_stats(firewall_ctx_t *ctx);
void fw_reset_stats(firewall_ctx_t *ctx);

// Helpers
void mac_to_string(unsigned char *mac, char *str);
void string_to_mac(const char *str, unsigned char *mac);
const char *action_to_string(fw_action_t action);
const char *protocol_to_string(uint8_t proto);
const char *rule_type_to_string(rule_type_t type);

#endif // FLAMEWALL_H
