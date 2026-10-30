#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "egress.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static bool (*g_permit)(void *, egress_kind_t, char *, size_t);
static void          *g_arg;
static unsigned long  g_refusals[EGRESS_KIND_MAX];

static const char *const KIND_NAME[EGRESS_KIND_MAX] = {
    "feeds", "telemetry", "ha", "gwmon"
};

void egress_bind(bool (*permit)(void *, egress_kind_t, char *, size_t),
                 void *arg) {
    pthread_mutex_lock(&g_lock);
    g_permit = permit;
    g_arg    = arg;
    pthread_mutex_unlock(&g_lock);
}

bool egress_permitted(egress_kind_t kind, char *why, size_t whylen) {
    if (kind < 0 || kind >= EGRESS_KIND_MAX) return false;
    if (why && whylen) why[0] = 0;

    pthread_mutex_lock(&g_lock);
    bool (*fn)(void *, egress_kind_t, char *, size_t) = g_permit;
    void *arg = g_arg;
    pthread_mutex_unlock(&g_lock);

    /*
     * Nothing bound means nothing has an opinion, which is not the same as
     * "deny". A build without the air gap compiled in, and every unit test
     * that links one of these subsystems on its own, must behave exactly as
     * it did before this gate existed.
     */
    if (!fn) return true;

    /*
     * Called OUTSIDE g_lock. The bound predicate takes the air gap's own
     * mutex, and holding two locks in a fixed order here would make the
     * pairing a property of every future caller rather than of this file.
     */
    bool ok = fn(arg, kind, why, whylen);

    if (!ok) {
        pthread_mutex_lock(&g_lock);
        g_refusals[kind]++;
        pthread_mutex_unlock(&g_lock);
    }
    return ok;
}

const char *egress_kind_name(egress_kind_t k) {
    if (k < 0 || k >= EGRESS_KIND_MAX) return "unknown";
    return KIND_NAME[k];
}

unsigned long egress_refusals(egress_kind_t k) {
    if (k < 0 || k >= EGRESS_KIND_MAX) return 0;
    pthread_mutex_lock(&g_lock);
    unsigned long n = g_refusals[k];
    pthread_mutex_unlock(&g_lock);
    return n;
}

void egress_reset_counters(void) {
    pthread_mutex_lock(&g_lock);
    memset(g_refusals, 0, sizeof(g_refusals));
    pthread_mutex_unlock(&g_lock);
}
