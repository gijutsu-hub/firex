#include <string.h>
#include <time.h>
#include "ratelimit.h"

void rate_limiter_init(rate_limiter_t *rl) {
    memset(rl, 0, sizeof(rate_limiter_t));
    pthread_mutex_init(&rl->lock, NULL);
}

void rate_limiter_cleanup(rate_limiter_t *rl) {
    pthread_mutex_destroy(&rl->lock);
}

bool rate_limiter_check(rate_limiter_t *rl, uint32_t ip, int pkt_size,
                        int max_pps, int max_bps) {
    pthread_mutex_lock(&rl->lock);

    time_t now = time(NULL);
    rate_entry_t *found = NULL;

    for (int i = 0; i < rl->count; i++) {
        if (rl->entries[i].ip == ip) {
            found = &rl->entries[i];
            break;
        }
    }

    if (!found) {
        if (rl->count < MAX_RATE_ENTRIES) {
            found = &rl->entries[rl->count++];
            found->ip = ip;
            found->packet_count = 0;
            found->byte_count = 0;
            found->window_start = now;
        } else {
            pthread_mutex_unlock(&rl->lock);
            return true; // Can't track, allow
        }
    }

    // Reset window if expired
    if (now - found->window_start >= RATE_LIMIT_WINDOW) {
        found->packet_count = 0;
        found->byte_count = 0;
        found->window_start = now;
    }

    found->packet_count++;
    found->byte_count += pkt_size;

    int elapsed = (now - found->window_start) > 0 ? (int)(now - found->window_start) : 1;
    int current_pps = found->packet_count / elapsed;
    int current_bps = found->byte_count / elapsed;

    bool allowed = true;
    if (max_pps > 0 && current_pps > max_pps) allowed = false;
    if (max_bps > 0 && current_bps > max_bps) allowed = false;

    pthread_mutex_unlock(&rl->lock);
    return allowed;
}

void rate_limiter_reset(rate_limiter_t *rl) {
    pthread_mutex_lock(&rl->lock);
    rl->count = 0;
    memset(rl->entries, 0, sizeof(rl->entries));
    pthread_mutex_unlock(&rl->lock);
}

int rate_limiter_get_count(rate_limiter_t *rl, uint32_t ip) {
    pthread_mutex_lock(&rl->lock);
    for (int i = 0; i < rl->count; i++) {
        if (rl->entries[i].ip == ip) {
            int c = rl->entries[i].packet_count;
            pthread_mutex_unlock(&rl->lock);
            return c;
        }
    }
    pthread_mutex_unlock(&rl->lock);
    return 0;
}
