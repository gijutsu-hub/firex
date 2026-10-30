#ifndef FIREX_CAPTURE_H
#define FIREX_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "vlan.h"

/*
 * Bounded packet capture, written as a classic libpcap file so Wireshark can
 * open it directly.
 *
 * Every capture is bounded three ways at once -- packets, bytes and seconds --
 * and whichever limit arrives first ends it. A diagnostic that can fill the
 * root filesystem of a firewall is not a diagnostic, so the caps are enforced
 * here rather than trusted to the caller, and only one capture runs at a time.
 *
 * libpcap is not linked. The filter is therefore a small fixed set --
 * interface, host, port, protocol -- matched in userspace rather than a BPF
 * program. It is narrower than tcpdump's syntax and it is honest about that.
 */

#define CAP_DEFAULT_PACKETS   1000
#define CAP_DEFAULT_SECONDS   30
#define CAP_DEFAULT_SNAPLEN   262144

#define CAP_MAX_PACKETS       200000
#define CAP_MAX_SECONDS       600
#define CAP_MAX_BYTES         (64UL * 1024 * 1024)
#define CAP_MIN_SNAPLEN       64

#define PCAP_MAGIC            0xa1b2c3d4u
#define PCAP_LINKTYPE_ETHERNET 1

typedef struct {
    char     ifname[IFNAME_LEN];
    uint32_t host;        /* 0 = any; matches either direction */
    uint16_t port;        /* 0 = any; matches either direction */
    uint8_t  proto;       /* 0 = any */
    int      snaplen;
    int      max_packets;
    int      max_seconds;
} capture_req_t;

typedef enum {
    CAP_IDLE = 0,
    CAP_RUNNING,
    CAP_DONE,
    CAP_FAILED
} capture_state_t;

typedef struct {
    capture_state_t state;
    capture_req_t   req;

    char            path[512];
    char            error[160];

    int             packets;      /* written */
    int             seen;         /* examined, before filtering */
    uint64_t        bytes;        /* file size so far */
    time_t          started, finished;

    int             sockfd;
    bool            running;
    pthread_t       thread;
    pthread_mutex_t lock;
} capture_ctx_t;

int  capture_init(capture_ctx_t *c);
void capture_shutdown(capture_ctx_t *c);

/*
 * Clamps the request to the caps above, then starts capturing into
 * <dir>/capture.pcap. Returns 0 on success; -1 with `error` filled when a
 * capture is already running, the interface is unusable, or the socket
 * cannot be opened (which on Linux means CAP_NET_RAW, so: root).
 */
int  capture_start(capture_ctx_t *c, const capture_req_t *req, const char *dir);

/* Ends an in-flight capture early; the file is complete and readable. */
void capture_stop(capture_ctx_t *c);

/* Copies the current state out under the lock. */
void capture_status(capture_ctx_t *c, capture_ctx_t *out);

/* Applies the caps. Exposed so the clamping is testable on its own. */
void capture_clamp(capture_req_t *r);

const char *capture_state_str(capture_state_t s);

#endif
