#ifndef FIREX_EGRESS_H
#define FIREX_EGRESS_H

#include <stdbool.h>
#include <stddef.h>

/*
 * The one gate the appliance's OWN outbound traffic passes through.
 *
 * Transit traffic -- packets belonging to the hosts behind the appliance --
 * is judged in inspect.c by airgap_verdict(). This header is about the other
 * half, and the half that decides whether an air gap is real: the
 * connections the appliance opens on its own behalf. Signature feeds,
 * syslog, NetFlow, config replication to an HA peer, gateway probes.
 *
 * An appliance that drops every user packet and then fetches its own
 * blocklist over the WAN is not air-gapped. It is a firewall with one
 * sanctioned tunnel through it, and that tunnel is the most valuable target
 * on the network, because it is the one path that is allowed to exist.
 *
 * WHY A BOUND HOOK RATHER THAN A DIRECT CALL. feeds.c, telemetry.c, ha.c
 * and gwmon.c have no business knowing what an air gap is, and their unit
 * tests have no business constructing one. They ask this header a yes/no
 * question about the network; firexd binds the answer to the air gap at
 * startup with one line. Nothing is bound in a test binary, and an unbound
 * gate permits -- so linking a subsystem on its own keeps its old behaviour
 * exactly.
 */

typedef enum {
    EGRESS_FEEDS,       /* threat-intelligence list refresh      */
    EGRESS_TELEMETRY,   /* syslog and NetFlow export             */
    EGRESS_HA,          /* configuration push to the peer        */
    EGRESS_GWMON,       /* gateway reachability probes           */
    EGRESS_KIND_MAX
} egress_kind_t;

/*
 * `permit` is asked before each outbound attempt and may write a short
 * operator-facing sentence into (why, whylen) when it refuses. Passing NULL
 * unbinds, which is what tests and the --check path want.
 */
void egress_bind(bool (*permit)(void *arg, egress_kind_t kind,
                                char *why, size_t whylen),
                 void *arg);

/*
 * May this subsystem talk to the network right now? `why` may be NULL.
 * Refusals are counted per kind so the console can show which subsystem is
 * being held back and by how much -- a number that stays at zero is how
 * this file's predecessor went unnoticed.
 */
bool egress_permitted(egress_kind_t kind, char *why, size_t whylen);

const char   *egress_kind_name(egress_kind_t k);
unsigned long egress_refusals(egress_kind_t k);
void          egress_reset_counters(void);

#endif /* FIREX_EGRESS_H */
