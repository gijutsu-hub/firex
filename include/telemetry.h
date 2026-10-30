#ifndef FIREX_TELEMETRY_H
#define FIREX_TELEMETRY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "conntrack.h"

/*
 * Shipping what the box sees to somewhere else: block events as RFC 5424
 * syslog, and connection flows as NetFlow v5.
 *
 * Both are one-way UDP by default and neither is allowed to block the
 * datapath: the exporter is its own thread, reads the block-event ring and
 * the connection table on a timer, and drops rather than waits if the
 * collector is gone.
 *
 * NetFlow v5 rather than v9 or IPFIX on purpose -- it is a fixed 48-byte
 * record with no template negotiation, so there is no state to get wrong and
 * every collector understands it. Its limits are real and worth knowing:
 * IPv4 only, and 32-bit counters.
 */

#define TELEM_HOST_LEN       128
#define NETFLOW_MAX_RECORDS  30      /* 24 + 30*48 = 1464, inside a 1500 MTU */
#define NETFLOW_V5_HDR_LEN   24
#define NETFLOW_V5_REC_LEN   48

/* RFC 5424 severities, the subset this emits. */
typedef enum {
    SYSLOG_ALERT    = 1,
    SYSLOG_CRIT     = 2,
    SYSLOG_ERR      = 3,
    SYSLOG_WARNING  = 4,
    SYSLOG_NOTICE   = 5,
    SYSLOG_INFO     = 6
} syslog_severity_t;

typedef struct {
    /* syslog */
    char     syslog_host[TELEM_HOST_LEN];
    uint16_t syslog_port;
    bool     syslog_tcp;            /* false = UDP */
    int      syslog_facility;       /* 0-23; 16 = local0 */
    int      syslog_min_severity;   /* send this severity and anything worse */

    /* netflow */
    char     netflow_host[TELEM_HOST_LEN];
    uint16_t netflow_port;
    int      netflow_interval;      /* seconds between exports */

    /* sampler */
    int      history_interval;
} telemetry_cfg_t;

typedef struct {
    telemetry_cfg_t cfg;

    int             syslog_fd;
    int             netflow_fd;
    uint32_t        flow_sequence;
    time_t          boot;

    int             event_cursor;   /* next block event to forward */

    unsigned long   syslog_sent, syslog_dropped;
    unsigned long   flows_sent, netflow_packets;

    bool            running;
    pthread_t       thread;
    pthread_mutex_t lock;
} telemetry_ctx_t;

int  telemetry_init(telemetry_ctx_t *t, const telemetry_cfg_t *cfg);
int  telemetry_start(telemetry_ctx_t *t);
void telemetry_stop(telemetry_ctx_t *t);
void telemetry_shutdown(telemetry_ctx_t *t);

/* Sends one message now, if a collector is configured and the severity
 * passes the threshold. Never blocks for long and never fails loudly. */
void telemetry_log(telemetry_ctx_t *t, syslog_severity_t sev,
                   const char *msgid, const char *fmt, ...)
     __attribute__((format(printf, 4, 5)));

/* Exports the current connection table once. Returns flows sent. */
int  telemetry_export_flows(telemetry_ctx_t *t);

bool telemetry_has_syslog(const telemetry_ctx_t *t);
bool telemetry_has_netflow(const telemetry_ctx_t *t);

/* ── pure builders, so the wire formats are testable without a socket ── */

/*
 * RFC 5424 frame into `out`. Returns the length written, or -1 if it does not
 * fit. `when` is the timestamp to stamp; pass 0 for "now".
 */
int syslog_format(char *out, size_t outlen, int facility, int severity,
                  time_t when, const char *hostname, const char *app,
                  const char *msgid, const char *msg);

/*
 * Builds a NetFlow v5 datagram from `n` entries (at most NETFLOW_MAX_RECORDS).
 * Returns the datagram length, or -1. All fields are big-endian on the wire.
 */
int netflow_v5_build(uint8_t *out, size_t outlen, const ct_entry_t *entries,
                     int n, uint32_t uptime_ms, time_t now, uint32_t sequence);

#endif
