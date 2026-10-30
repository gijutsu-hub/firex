# FireX → pfSense Parity Roadmap

Status as of 2026-10-28. **Phases 1 to 8 are complete** — see §4. FireX is **27,756 lines of C** (6,204 when this document was first written). pfSense is roughly
half a million lines of PHP on top of FreeBSD's `pf`, plus FRR, strongSwan,
OpenVPN and a package ecosystem — about twenty years of work.

Full parity is not a project with an end date. What follows is the honest
map: what FireX already does, where it stops, and the order in which closing
the gaps actually pays off.

---

## 1. What FireX has today

These are implemented and tested (53 assertions across `make test-all`):

| Area | Depth |
|---|---|
| Packet filtering L2–L4 | MAC, IP/CIDR/range, port/range, protocol, ethertype |
| Engines | AF_PACKET raw, NFQUEUE, XDP/eBPF native |
| 802.1Q VLANs | tag/untag, PVID, trunk/access/hybrid, QinQ unwrap, hopping detection |
| Zone matrix | 8 zones, deny-by-default forwarding |
| Inter-VLAN ACLs | 5-tuple, priority-ordered, evaluated before blanket policy |
| DPI | POSIX regex + raw content match on payload |
| Rate limiting | per-rule pps and bps |
| NAT | masquerade out, DNAT port forwards |
| WAN | DHCP / static / PPPoE config generation |
| DHCP | dnsmasq generation, per-VLAN scopes, static reservations |
| Block page | branded, XSS-escaped, CSP, event log |
| Web console | read-only JSON API + static UI |

That is a credible **segmentation firewall**. It is not yet a **router platform**.

---

## 2. The structural gap that blocked everything else — now closed

This section described the original blocker. It has been fixed; it is kept
because it explains why the roadmap is ordered the way it is.

> Before any feature comparison: FireX has **no write path for its own
> config.** `vlan_save_config()` is declared and never implemented.
> `fw_save_config()` persists packet rules only. The console returns
> `405 read-only` on every mutation. There is no `SIGHUP` reload. Changing
> anything means hand-editing `firex.conf` and restarting the daemon.

**What now exists** (`src/config_write.c`, `configstore.c`, `reload.c`,
`auth.c`, rewritten `webui.c`):

- Full serialiser, verified as the exact inverse of the parser: the shipped
  configs round-trip field for field, and a second save is byte-identical
- Versioned store at `/etc/firex/config.d/NNNNN.conf`, append-only history
  with author, timestamp and note; a rollback records itself as a new revision
- `SIGHUP` → parse into throwaway contexts → validate → swap → re-provision,
  restoring the previous configuration automatically when provisioning fails
- 22 semantic validation rules (subnet overlap, gateway placement, DHCP pool
  containment, duplicate WAN ports, shell-unsafe interface names and more)
- `--check` exits non-zero on a bad config and gates `ExecStartPre`
- Console authentication: SHA-512 crypt, roles, HttpOnly session cookies,
  double-submit CSRF, per-source login throttling
- Writable API behind auth, plus backup and validated restore

100 tests cover it (`make test-config`).


## 3. Gap table

Legend: ●● solid · ◐ partial · ○ absent

### Firewall
| pfSense | FireX | Note |
|---|---|---|
| Stateful rules | ◐ | iptables conntrack does the work; FireX keeps no state table of its own |
| Aliases (reusable host/port groups) | ●● | network and port sets, `$NAME` |
| Schedules (time-based rules) | ●● | midnight-crossing windows included |
| Floating rules | ○ | |
| Port forward / DNAT | ●● | |
| 1:1 NAT, outbound NAT rules | ○ | only blanket masquerade |
| Virtual IPs | ○ | |

### Interfaces & routing
| pfSense | FireX | Note |
|---|---|---|
| VLANs / QinQ | ●● | strongest area |
| LAGG, bridges | ○ | |
| GRE / GIF tunnels | ○ | |
| Static routes | ●● | parsed, validated, installed |
| Gateway groups, multi-WAN failover | ●● | ICMP monitoring with hysteresis drives the default route |
| Policy-based routing | ○ | |
| Dynamic routing (OSPF/BGP via FRR) | ○ | |

### VPN
| pfSense | FireX | Note |
|---|---|---|
| IPsec (IKEv1/v2) | ◐ | site-to-site with PSK; no certificates |
| OpenVPN server/client | ○ | not started |
| WireGuard | ●● | keys, peers, per-peer zones |

### Services
| pfSense | FireX | Note |
|---|---|---|
| DHCP server | ●● | via dnsmasq |
| DHCP relay | ○ | |
| DNS resolver (Unbound, DNSSEC) | ◐ | dnsmasq forwarding only |
| Dynamic DNS | ○ | |
| NTP server | ○ | |
| Captive portal | ●● | sessions, vouchers, RADIUS PAP |
| Load balancer | ○ | |
| UPnP / SNMP | ○ | |

### High availability
| pfSense | FireX | Note |
|---|---|---|
| CARP virtual IPs | ●● | VRRP, the Linux equivalent |
| pfsync state sync | ●● | conntrackd, FTFW mode |
| XMLRPC config sync | ●● | HMAC-signed HTTP push |

### Traffic shaping
| pfSense | FireX | Note |
|---|---|---|
| ALTQ queues (HFSC/CBQ/PRIQ) | ●● | HTB, the Linux equivalent |
| Limiters (dummynet) | ●● | per-VLAN HTB classes |
| CoDel / FQ-CoDel | ●● | plus CAKE and SFQ |
| Per-rule rate limit | ●● | FireX has this, pfSense does it via limiters |

### Auth & certificates
| pfSense | FireX | Note |
|---|---|---|
| Console authentication | ●● | sessions, CSRF, roles, throttle |
| Local users, groups, privileges | ◐ | admin/viewer roles; passwords from the web console, no user creation in the UI |
| LDAP / RADIUS / 2FA | ◐ | RADIUS for the portal only, not the console |
| Certificate manager (CA, certs, CRL) | ○ | blocks road-warrior IPsec |

### Monitoring & diagnostics
| pfSense | FireX | Note |
|---|---|---|
| Live counters | ◐ | per-VLAN rx/blocked in API |
| RRD / historical graphs | ◐ | in-memory ring, lost on restart |
| State table viewer | ●● | reads the kernel's conntrack |
| Packet capture (pcap) | ●● | bounded; no BPF expression syntax |
| Syslog local + remote | ●● | RFC 5424 over UDP or TCP |
| NetFlow export | ◐ | v5; no v9 or IPFIX |

### System
| pfSense | FireX | Note |
|---|---|---|
| Versioned config + rollback | ●● | `/etc/firex/config.d/`, append-only |
| Backup / restore | ●● | download + validated upload |
| Package manager | ●● | signed bundles; no dependency resolution |
| Firmware upgrade (A/B) | ●● | Ed25519, 3-attempt auto-rollback; no delta |
| Console menu | ●● | 15 options on ttyS0, password-gated |
| Graphical boot screen | ●● | GRUB theme + Plymouth, generated from `brand.h` |
| Local GUI console | ●● | GTK4 kiosk on the appliance's own screen, a client of the daemon |
| Shipped default credentials | ●● | root/root, admin/admin, warned about until changed |

### Security add-ons
| pfSense | FireX | Note |
|---|---|---|
| Snort / Suricata IDS-IPS | ◐ | own engine; no reassembly or PCRE |
| pfBlockerNG (IP/DNS blocklists) | ●● | address and domain feeds |
| Malware / payload scanning | ◐ | per-packet patterns; no file scanning |

---

## 4. Phased roadmap

Sized in rough engineering weeks for one developer. Phases are ordered by
*unlock value*, not by how impressive the feature sounds.

### Phase 1 — The config spine ✅ **DONE**

1. ✅ `firex_save_enterprise_config()` / `vlan_save_config()` round-trip
2. ✅ Persistence covers WAN, NAT, forwards, zones, ACLs, portal
3. ✅ Versioned store `/etc/firex/config.d/NNNNN.conf`, append-only
4. ✅ `SIGHUP` → validate → stage → apply → rollback-on-failure
5. ✅ `--check` dry-run validator, wired into `ExecStartPre`
6. ✅ Console auth: SHA-512 crypt, sessions, CSRF, roles, login throttle
7. ✅ Writable API behind auth (VLAN edit, matrix, save/apply/rollback)
8. ✅ Backup download and validated restore upload

**Left out of this phase, deliberately:**
- No user-management API — accounts are added by editing `/etc/firex/users`
  (`auth_add_user()` exists and is tested; no endpoint is wired to it)
- VLAN create and delete are not exposed; only edit is
- No TLS, so the session cookie cannot carry `Secure`


### Phase 2 — Router fundamentals ✅ **DONE**

9.  ✅ Aliases — named network and port sets, referenced as `$NAME`, resolved
    at match time so editing one changes every rule that uses it
10. ✅ Schedules — recurring windows, including ones that cross midnight;
    a rule outside its window is skipped and evaluation continues
11. ✅ Static routes — parsed, validated, installed, serialised
12. ✅ Gateway monitoring — ICMP probes per link with consecutive-result
    thresholds, rolling loss and averaged RTT
13. ✅ Multi-WAN failover — `failover_priority` now decides which link carries
    the default route; the others are parked at a high metric
14. ⬜ Outbound NAT rules + 1:1 NAT — **not done**, still blanket masquerade

**Left out of this phase, deliberately:**
- Policy-based routing (per-rule gateway selection)
- A UI for creating schedules and routes; both are config-file only, while
  aliases are fully editable from the console
- Load balancing across links — failover picks one link, it does not share


### Phase 3 — VPN ✅ **DONE**

15. ✅ WireGuard — interfaces, peers, generated `wg-quick` configuration
16. ✅ Key management — X25519 via OpenSSL, `--genkey` / `--genpsk` and a
    console button; the private key is shown once and never echoed back
17. ✅ Per-peer zone assignment — each peer carries a zone, and `vpn_zone_for()`
    maps an address to it by longest prefix, so peers sharing one interface
    are held to different rows of the forwarding matrix
18. ✅ IPsec — site-to-site, strongSwan `swanctl.conf` plus a separate
    secrets file, IKEv2 by default with IKEv1 allowed under a warning
19. ⬜ OpenVPN — **not done**
20. ⬜ Road-warrior IPsec (IKEv2 EAP/certificates) — **not done**, PSK only

**Also closed here:** traffic *to* a tunnel used to skip forwarding policy
entirely, because no VLAN owned the destination. `vlan_check_zones()` now
decides those flows.

**Left out of this phase, deliberately:**
- No certificate manager; IPsec authenticates with pre-shared keys only
- Peers can be added and deleted from the console but not edited in place
- Live peer statistics (handshake time, byte counters) are modelled and
  serialised but never populated — nothing reads them back from the kernel yet


### Phase 4 — Visibility ✅ **DONE**

19. ✅ State table viewer — reads the kernel's conntrack rather than keeping a
    second one, from procfs or conntrack-tools, and says which; when neither
    is available it explains why and still reports the real occupancy
20. ✅ Packet capture — bounded by packets, seconds *and* bytes at once,
    written as a classic libpcap file and downloadable from the console
21. ✅ Historical counters — a 1440-slot in-memory ring with inline SVG
    sparklines; cumulative counters are stored as per-interval deltas
22. ✅ Remote syslog (RFC 5424, UDP and TCP) and NetFlow v5 export

**Left out of this phase, deliberately:**
- No libpcap, so capture filtering is interface/host/port/protocol rather
  than tcpdump expression syntax
- History is in memory only and is lost on restart; pfSense persists RRDs
- NetFlow v9 and IPFIX; v5 is IPv4-only with 32-bit counters, and a flow
  larger than 4 GB saturates rather than wrapping
- NetFlow flow durations are stamped at export time: the connection table
  gives a remaining TTL, not a start time, so they are honestly unknown


### Phase 5 — Shaping & portal ✅ **DONE**

23. ✅ tc/HTB class hierarchy, per VLAN, classified by source subnet, with
    802.1p priority inverted into tc's ordering
24. ✅ FQ-CoDel (or CAKE, or SFQ) as the leaf under every class — the part
    that actually makes a saturated link feel fast
25. ✅ Captive portal for real: login page, session table with idle and hard
    timeouts, vouchers, and a RADIUS PAP client

**What this replaced:** a `tbf` token bucket on each VLAN interface, which
enforced a rate and left bufferbloat exactly where it was; and a portal
intercept that redirected an ipset nothing ever populated. `bandwidth_up_mbps`
had been parsed, serialised and editable since Phase 1 while doing nothing at
all.

**Left out of this phase, deliberately:**
- Ingress shaping needs an IFB device and costs a copy of every inbound
  packet, so it is opt-in and off by default
- No per-host or per-connection fairness beyond what FQ-CoDel gives for free
- The portal has no MAC-based sessions, no RADIUS accounting, no
  CoA/Disconnect, and no MSCHAPv2 — PAP only, so the shared secret and the
  transport are doing all the work
- HTTPS cannot be intercepted without terminating TLS, so those flows are
  reset rather than redirected


### Phase 6 — High availability ✅ **DONE**

26. ✅ VRRP virtual addresses — keepalived configuration generated from the
    VLAN table; every gateway becomes a floating address, and the node stops
    assigning them statically so two nodes never answer for one address
27. ✅ Connection sync — conntrackd in FTFW mode over the dedicated link, so
    established connections survive a failover rather than resetting
28. ✅ Config replication — the primary pushes to the secondary on every
    saved revision, authenticated by HMAC-SHA256 over the body *and* the
    timestamp, so a captured push cannot be replayed with a fresh header

**Why the HMAC rather than a session:** the peer is a machine. Giving it a
console account would mean a credential that also works for everything else.
The signature proves the sender holds the shared secret and that the body
arrived unaltered, and the receiving node needs no user for the sending one.

**Left out of this phase, deliberately:**
- Both nodes start as VRRP BACKUP and let priority decide. Declaring the
  primary MASTER makes it claim the addresses before hearing from the peer,
  which is how a restart produces two masters
- VRRPv2 only, so `vrrp_password` is 8 significant characters and the
  validator says so rather than letting a longer one look stronger
- No automatic failback of state beyond what keepalived's preempt does, no
  split-brain arbitration beyond priority, and no third witness node
- Replication is one-way: a secondary refuses to push. Two-way sync needs a
  conflict rule, and "last write wins" between firewalls is not one


### Phase 7 — Threat layer ✅ **DONE**

29. ✅ Signature matching — an Aho-Corasick automaton, so every pattern is
    matched in one pass and the thousandth signature costs what the first
    did. A documented subset of the Snort rule syntax, with hex patterns,
    nocase, offset and depth
30. ✅ Payload scanning — the same engine, class-filtered: `ips` applies the
    whole ruleset, `malware_scan` only the malware and C2 classes
31. ✅ Blocklist feeds — addresses as merged sorted ranges, domains matched
    on label boundaries, fetched over verified HTTPS or from a local file
32. ✅ Auto-response — detections accumulate a score, blocking happens at a
    threshold, repeats are held longer, quiet hosts decay back to nothing

**ZONE_QUARANTINE is no longer dead.** A host under response is evaluated as
QUARANTINE, so what it may still reach is the operator's row of the
forwarding matrix rather than a rule hardcoded in the response engine. The
validator warns when that row denies nothing, because quarantine would then
be an action that changes nothing.

**What this is not.** There is no stream reassembly, no flow tracking, no
PCRE and no protocol parsers. A signature matches inside one packet, so a
pattern split across two segments is missed. That is a real limit and the
console says so rather than implying Suricata.

**Left out of this phase, deliberately:**
- Signatures run before the firewall rules, not after: a drop rule should
  beat an allow rule, and scanning only what the rules already permitted
  would let a known exploit through an open port
- Shipped in alert-only mode. A drop rule reports and lets traffic through
  until `inline` is turned on, which is how a ruleset should be deployed
- No ClamAV or file reassembly, so "payload scanning" means pattern matching
  on packets, not scanning files
- No automatic rule updates from an upstream feed; rules are a local file


### Phase 8 — Platform ✅ **built**
33. **Package system** — `src/pkg.c`. A package is an ordinary signed
    bundle whose payload is a tarball, so there is one signature scheme
    and one verifier rather than two. Installation lists the archive
    first and refuses the whole package if any member name fails the
    path whitelist, climbs out of the root with `..`, or is a symbolic
    or hard link. Extraction drops ownership and modes, so a package
    cannot ship a setuid-root binary.
34. **A/B update partitions + signed images** — `src/update.c`,
    `src/slots.c`, `tools/firex-bundle.c`. Ed25519 over a canonical
    metadata string plus a SHA-256 of the payload, so editing any header
    field or any payload byte is a refusal with a reason. Two root slots
    and a shared data partition; the running slot is never written. A
    freshly installed slot gets three boot attempts and is marked bad if
    `firexd` never starts, at which point `grub.cfg` is rewritten and
    the appliance returns to the slot that worked.
35. **Console menu (pfSense-style serial UI)** — `src/console.c`.
    Fifteen options on `ttyS0`, gated by the same user database as the
    web console. Destructive options confirm; input is parsed strictly,
    so `13x` is refused rather than read as "reboot".

See **[UPDATES-AND-PACKAGES.md](UPDATES-AND-PACKAGES.md)** for the bundle
format, the slot state machine and what is deliberately not built.

36. **Boot screen** — `tools/make-splash.py`, `board/plymouth/firex/`,
    `board/grub/themes/firex/`. A GRUB theme and a Plymouth script theme,
    both drawn from `include/brand.h`, so a re-skin is one header and
    `make splash`. The artwork is committed as PNGs, so the image build
    needs no Pillow and no font stack. Every step in `grub.cfg` is
    guarded and the plain text menu is selected first, so a missing font,
    theme or video driver costs the artwork and not the boot.
37. **Shipped credentials, said out loud** — `src/auth.c`, `src/webui.c`.
    The appliance goes out as root/root and admin/admin, each enrolled in
    both the Linux and the FireX database so either pair works over SSH
    and in the web console. `auth_list()` reports which accounts are
    still at the shipped password by comparing the stored hash, not by
    any bookkeeping a reload could lose, and *System → Accounts* changes
    either database. Setting a password back to the account name is
    refused, so the banner cannot be cleared without actually changing
    something.

**Rough total to credible pfSense-class: 6–9 months of focused work.**

---

## 5. Where FireX can beat pfSense

Worth being deliberate about, rather than only chasing parity:

- **XDP/eBPF fast path.** pfSense has no equivalent — pf runs in the FreeBSD
  network stack. FireX drops at the driver, before `sk_buff` allocation.
  This is a genuine architectural advantage.
- **Segmentation as a first-class model.** The zone matrix and inter-VLAN ACL
  engine are cleaner than pfSense's interface-group approach.
- **Image size.** 590 MB on disk today, and a Buildroot/Alpine variant could
  reach 80–150 MB. pfSense ships ~700 MB+.
- **Branded block page out of the box.** pfSense has nothing comparable.

---

## 6. Where this leaves things

Phase 1 is built and tested. FireX can now save its own configuration, version
it, validate it before applying, roll back when an apply fails, and refuse an
unauthenticated write. That is the spine the rest of the roadmap hangs off.

Phase 2 is built and tested too. Aliases and schedules make the rule table
usable at scale, and the gateway monitor turned the dead `failover_priority`
field into real failover — verified live by breaking a link's monitor target
and watching the default route move, then come back.

Phase 3 is built and tested. WireGuard peers are a table that serialises,
validates and reloads like everything else, and each one carries its own zone,
so a branch office and a contractor laptop can share a tunnel interface and
still be held to different policy.

Phase 4 is built and tested. The box can now be watched as well as
configured: live counters, the kernel's connection table, a bounded packet
capture, and export to a syslog or NetFlow collector.

Phase 5 is built and tested. The two largest half-built things in the
codebase are now whole: bandwidth limits that were parsed but never applied,
and a portal that redirected clients to a login page that did not exist.

Phase 6 is built and tested. A pair of appliances can now share the gateway
addresses, keep established connections through a failover, and stay in step
on configuration without anyone remembering to copy a file.

Phase 7 is built and tested, and **nothing in the codebase is marked NOT
BUILT any more.** The slots at `src/inspect.c` that had held empty comments
since the first version are filled, and `ips_enabled`, `malware_scan` and
`ZONE_QUARANTINE` all do something — the last of the dead fields this
roadmap started by cataloguing.

**Phase 8 is built.** The package system, A/B update partitions with signed
images and the serial console menu are in place, and none of it changed what
the appliance does on the wire — that was the point. FireX is now a product
that can be shipped and updated rather than a firewall that has to be
rebuilt.

The eight phases are done. What is left is not a ninth phase of the same
kind; it is the list of things each phase deliberately left out, gathered in
§3 and in each phase's own notes. The honest headline items:

- **No secure boot.** The signature protects the update path, not the boot
  path. Someone with physical access can write a slot directly.
- **No key rotation protocol.** Revoking a compromised signing key means
  editing `/etc/firex/update-keys` on each appliance by hand.
- **No delta updates.** A bundle carries a whole root filesystem.
- **OpenVPN, a certificate manager, IPFIX, RRD persistence, two-way HA
  replication and stream reassembly for signatures** remain out of scope,
  each for the reasons given where it was skipped.

None of those is a gap in what was asked for. They are the next honest
conversation.

The original reasoning, kept because it still holds for the phases ahead:

> Build **Phase 1** next, in full, before anything else. The temptation is to
> start with WireGuard or IDS because those are the features people ask for by
> name. Resist it.
