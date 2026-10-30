/*
 * Bounded packet capture to a libpcap file. See include/capture.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#include "capture.h"
#include "firewall.h"
#include "netutil.h"
#include "brand.h"

const char *capture_state_str(capture_state_t s) {
    switch (s) {
        case CAP_RUNNING: return "running";
        case CAP_DONE:    return "done";
        case CAP_FAILED:  return "failed";
        default:          return "idle";
    }
}

int capture_init(capture_ctx_t *c) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);
    c->sockfd = -1;
    return 0;
}

void capture_clamp(capture_req_t *r) {
    if (r->snaplen <= 0)              r->snaplen = CAP_DEFAULT_SNAPLEN;
    if (r->snaplen < CAP_MIN_SNAPLEN) r->snaplen = CAP_MIN_SNAPLEN;
    if (r->snaplen > CAP_DEFAULT_SNAPLEN) r->snaplen = CAP_DEFAULT_SNAPLEN;

    if (r->max_packets <= 0)              r->max_packets = CAP_DEFAULT_PACKETS;
    if (r->max_packets > CAP_MAX_PACKETS) r->max_packets = CAP_MAX_PACKETS;

    if (r->max_seconds <= 0)              r->max_seconds = CAP_DEFAULT_SECONDS;
    if (r->max_seconds > CAP_MAX_SECONDS) r->max_seconds = CAP_MAX_SECONDS;
}

/* ── pcap file format ───────────────────────────────────────────────── */

struct pcap_file_hdr {
    uint32_t magic;
    uint16_t version_major, version_minor;
    int32_t  thiszone;
    uint32_t sigfigs, snaplen, network;
};

struct pcap_pkt_hdr {
    uint32_t ts_sec, ts_usec, incl_len, orig_len;
};

static int write_pcap_header(FILE *f, int snaplen) {
    struct pcap_file_hdr h;
    memset(&h, 0, sizeof(h));
    h.magic         = PCAP_MAGIC;
    h.version_major = 2;
    h.version_minor = 4;
    h.snaplen       = (uint32_t)snaplen;
    h.network       = PCAP_LINKTYPE_ETHERNET;
    return fwrite(&h, sizeof(h), 1, f) == 1 ? 0 : -1;
}

/* ── filtering ──────────────────────────────────────────────────────── */

static bool matches(const capture_req_t *r, const packet_info_t *p) {
    if (r->proto && (!p->has_ip || p->protocol != r->proto)) return false;

    if (r->host) {
        if (!p->has_ip) return false;
        if (p->src_ip != r->host && p->dst_ip != r->host) return false;
    }
    if (r->port) {
        if (!p->has_ip) return false;
        if (p->src_port != r->port && p->dst_port != r->port) return false;
    }
    return true;
}

/* ── capture thread ─────────────────────────────────────────────────── */

static void finish(capture_ctx_t *c, capture_state_t st, const char *err) {
    pthread_mutex_lock(&c->lock);
    c->state    = st;
    c->finished = time(NULL);
    c->running  = false;
    if (err) snprintf(c->error, sizeof(c->error), "%s", err);
    if (c->sockfd >= 0) { close(c->sockfd); c->sockfd = -1; }
    pthread_mutex_unlock(&c->lock);
}

static void *cap_thread(void *arg) {
    capture_ctx_t *c = arg;

    FILE *f = fopen(c->path, "wb");
    if (!f) { finish(c, CAP_FAILED, strerror(errno)); return NULL; }
    if (write_pcap_header(f, c->req.snaplen) != 0) {
        fclose(f);
        finish(c, CAP_FAILED, "could not write the pcap header");
        return NULL;
    }

    unsigned char *buf = malloc(65536);
    if (!buf) { fclose(f); finish(c, CAP_FAILED, "out of memory"); return NULL; }

    uint64_t written = sizeof(struct pcap_file_hdr);
    time_t deadline = c->started + c->req.max_seconds;
    const char *stop_reason = NULL;

    while (c->running) {
        if (time(NULL) >= deadline)              { stop_reason = "time limit";   break; }
        if (c->packets >= c->req.max_packets)    { stop_reason = "packet limit"; break; }
        if (written >= CAP_MAX_BYTES)            { stop_reason = "size limit";   break; }

        ssize_t n = recv(c->sockfd, buf, 65536, 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            stop_reason = strerror(errno);
            break;
        }

        pthread_mutex_lock(&c->lock);
        c->seen++;
        pthread_mutex_unlock(&c->lock);

        packet_info_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        parse_packet(buf, (int)n, &pkt);
        if (!matches(&c->req, &pkt)) continue;

        int incl = (n < c->req.snaplen) ? (int)n : c->req.snaplen;

        struct timeval tv;
        gettimeofday(&tv, NULL);
        struct pcap_pkt_hdr ph = {
            .ts_sec   = (uint32_t)tv.tv_sec,
            .ts_usec  = (uint32_t)tv.tv_usec,
            .incl_len = (uint32_t)incl,
            .orig_len = (uint32_t)n
        };
        if (fwrite(&ph, sizeof(ph), 1, f) != 1 ||
            fwrite(buf, 1, (size_t)incl, f) != (size_t)incl) {
            stop_reason = "write failed";
            break;
        }
        written += sizeof(ph) + (uint64_t)incl;

        pthread_mutex_lock(&c->lock);
        c->packets++;
        c->bytes = written;
        pthread_mutex_unlock(&c->lock);
    }

    free(buf);
    fflush(f);
    fclose(f);

    printf("[%s] capture finished: %d packet(s) of %d seen, %llu bytes (%s)\n",
           BRAND_PRODUCT, c->packets, c->seen,
           (unsigned long long)written,
           stop_reason ? stop_reason : "stopped");

    finish(c, CAP_DONE, NULL);
    return NULL;
}

int capture_start(capture_ctx_t *c, const capture_req_t *req, const char *dir) {
    pthread_mutex_lock(&c->lock);
    if (c->state == CAP_RUNNING) {
        pthread_mutex_unlock(&c->lock);
        snprintf(c->error, sizeof(c->error), "a capture is already running");
        return -1;
    }
    pthread_mutex_unlock(&c->lock);

    capture_req_t r = *req;
    capture_clamp(&r);

    if (!r.ifname[0] || !fx_ifname_safe(r.ifname, IFNAME_LEN)) {
        snprintf(c->error, sizeof(c->error), "'%s' is not a usable interface",
                 r.ifname);
        c->state = CAP_FAILED;
        return -1;
    }

    /* The capture directory is normally on tmpfs and gone after a reboot,
     * which is the right lifetime for a diagnostic. */
    struct stat dst;
    if (stat(dir, &dst) != 0 && mkdir(dir, 0700) != 0) {
        snprintf(c->error, sizeof(c->error), "cannot create %s (%s)",
                 dir, strerror(errno));
        c->state = CAP_FAILED;
        return -1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        snprintf(c->error, sizeof(c->error),
                 "cannot open a capture socket (%s); this needs CAP_NET_RAW",
                 strerror(errno));
        c->state = CAP_FAILED;
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", r.ifname);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        snprintf(c->error, sizeof(c->error), "no such interface: %s", r.ifname);
        close(fd);
        c->state = CAP_FAILED;
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifr.ifr_ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        snprintf(c->error, sizeof(c->error), "bind to %s failed: %s",
                 r.ifname, strerror(errno));
        close(fd);
        c->state = CAP_FAILED;
        return -1;
    }

    /* So the loop can notice its deadline and an early stop. */
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    pthread_mutex_lock(&c->lock);
    c->req      = r;
    c->sockfd   = fd;
    c->packets  = 0;
    c->seen     = 0;
    c->bytes    = 0;
    c->started  = time(NULL);
    c->finished = 0;
    c->error[0] = '\0';
    c->state    = CAP_RUNNING;
    c->running  = true;
    snprintf(c->path, sizeof(c->path), "%s/capture.pcap", dir);
    pthread_mutex_unlock(&c->lock);

    if (pthread_create(&c->thread, NULL, cap_thread, c) != 0) {
        close(fd);
        pthread_mutex_lock(&c->lock);
        c->sockfd = -1;
        c->state  = CAP_FAILED;
        c->running = false;
        snprintf(c->error, sizeof(c->error), "could not start the capture thread");
        pthread_mutex_unlock(&c->lock);
        return -1;
    }

    printf("[%s] capture started on %s: at most %d packets, %ds, snaplen %d\n",
           BRAND_PRODUCT, r.ifname, r.max_packets, r.max_seconds, r.snaplen);
    return 0;
}

void capture_stop(capture_ctx_t *c) {
    pthread_mutex_lock(&c->lock);
    bool was = c->running;
    c->running = false;
    pthread_mutex_unlock(&c->lock);
    if (was) pthread_join(c->thread, NULL);
}

void capture_status(capture_ctx_t *c, capture_ctx_t *out) {
    pthread_mutex_lock(&c->lock);
    *out = *c;
    pthread_mutex_unlock(&c->lock);
}

void capture_shutdown(capture_ctx_t *c) {
    if (!c) return;
    capture_stop(c);
    if (c->sockfd >= 0) { close(c->sockfd); c->sockfd = -1; }
    pthread_mutex_destroy(&c->lock);
}
