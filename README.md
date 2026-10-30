# FireX by Sumon — *The Hidden Defend Layer*

A Linux network security appliance: packet filtering with deep packet
inspection, 802.1Q VLAN segmentation with zone-based forwarding, WAN/NAT/DHCP
provisioning, signature and reputation-based threat detection, live malware
scanning of transfers, enforced air-gap isolation, and a branded block page.

It ships as a bootable BIOS+UEFI image with A/B update slots, signed update
bundles, a web console, a desktop console on the appliance's own screen, and
a serial menu — four views of one daemon rather than four opinions about it.

Two binaries, one engine:

| Binary | What it is |
|---|---|
| **`firexd`** | Headless appliance daemon. What the boot scripts run. |
| **`flamewall`** | GTK4 console for interactive use on a desktop. |

## Build

```bash
make deps     # Ubuntu/Debian: gtk4, libnetfilter_queue, libbpf, clang, iptables
make
```

Produces `firexd`, `flamewall` and `xdp/xdp_firewall.bpf.o`.

## Run

```bash
./firexd --dump -c config/firex.conf        # review the config, changes nothing
sudo ./firexd -c config/firex.conf          # full appliance
make console                                # console + throwaway daemon, no root
```

`make console` is the quickest look at it: it starts a daemon with
`--no-apply` — which parses the configuration and serves the API without
touching this machine's interfaces, routes or firewall rules — opens the
desktop console against it, and stops the daemon again when you close the
window. Sign in as `admin` / `admin`. Add `CONSOLE_ARGS="--kiosk"` to see it
the way the appliance runs it.

`--dump` prints the parsed VLANs, ports, zone matrix, ACLs and published
services without touching the network — use it before pointing this at
anything live.

## Packet engines

| Engine | What it does | Needs |
|---|---|---|
| **Raw Socket** | Monitor only. Sees every frame, cannot block. | `AF_PACKET` (root) |
| **NFQUEUE** | Real filtering, both directions, per-packet verdicts. | iptables + libnetfilter_queue (root) |
| **XDP/eBPF** | Kernel-level, drops in the driver. **Ingress only**, no DPI. | clang + libbpf (root) |

Starting NFQUEUE or XDP **modifies live kernel state**. Both clean up on exit;
if the process is killed, remove leftovers by hand:

```bash
sudo iptables -D INPUT -i eth0 -j NFQUEUE --queue-num 0
sudo ip link set dev eth0 xdp off
```

## Segmentation

`config/firex.conf` drives everything:

- **VLANs** — subnet, SVI gateway, DHCP scope, bandwidth, per-segment policy flags
- **Ports** — access / trunk / hybrid / mirror, PVID, allowed VLAN list, storm control
- **Zones** — nine security zones with a deny-by-default forwarding matrix:

  | Zone | What belongs in it |
  |---|---|
  | `WAN` | untrusted upstream |
  | `LAN` | trusted corporate |
  | `DMZ` | semi-trusted public services |
  | `GUEST` | untrusted internal — visitors |
  | `IOT` | restricted devices |
  | `VOIP` | voice, QoS-prioritised |
  | `MGMT` | appliance management only |
  | `QUARANTINE` | hosts isolated by auto-response |
  | `VPN` | remote peers over WireGuard or IPsec |

  New zones are appended before `ZONE_MAX`, so existing values stay put and a
  configuration written before a zone existed simply has no policy lines for
  it — and the matrix defaults to deny, which is the safe direction.
- **ACLs** — 5-tuple inter-VLAN rules, priority-ordered
- **WAN** — DHCP / static / PPPoE, dual-link with failover metrics, bogon filtering
- **NAT** — per-VLAN masquerade, only for segments granted internet access
- **DNAT** — published services with optional source restriction

### Decision order

A packet's fate is decided in this order, first match winning:

1. **VLAN membership** — a tag the ingress port is not allowed to carry is
   dropped as VLAN hopping
2. **Client isolation** — intra-segment traffic on an isolated VLAN
3. **Explicit ACL rules**, in priority order
4. **`inter_vlan_routing`** — the VLAN's blanket routing switch
5. **Zone matrix** — source zone → destination zone
6. **Firewall rule table** — the MAC/IP/port/protocol/DPI rules

Step 3 deliberately precedes step 4. A specific rule has to be able to carve an
exception out of a default posture, otherwise an entry like *"IOT MQTT to
controller"* on a VLAN with `inter_vlan_routing = no` could never match and
would sit in the config looking effective while doing nothing.

## Block page

A branded HTTP portal (default `:8080`) that tells a user why a request was
stopped: reason, policy reference, segment, zone, timestamp and a request ID
for support. For plaintext HTTP, FireX forges a 302 from the origin server's
address so the browser lands on the page instead of timing out.

**HTTPS cannot be branded.** Without terminating TLS there is no way to
substitute a page, so quarantined HTTPS flows get a TCP reset and the browser
shows its own connection error. Closing that gap means a MITM proxy with a CA
deployed to managed endpoints — not built here.

Everything attacker-controlled that reaches the page (the `Host:` header above
all) is HTML-escaped; the page carries a restrictive CSP.

## Threat detection

Four layers, cheapest first, each one deciding before the next runs.

| Layer | What it matches | Where |
|---|---|---|
| **Reputation feeds** | addresses and domains, from lists refetched on a schedule | `src/feeds.c` |
| **Signatures** | byte patterns inside **one packet**, Aho-Corasick | `src/ids.c` |
| **Malware** | the **whole transferred object**, reassembled and hashed | `src/malware.c` |
| **Auto-response** | hosts that keep tripping the above | `src/response.c` |

Signature matching runs before the firewall rules, not after: a signature
that says drop should win over a rule that says allow. Scanning only what the
rules already permitted would save work and let a known exploit through an
open port.

### Live malware protection

`src/ids.c` matches inside a single packet, and its own header is honest
about the limit — *a pattern split across two segments is missed*. Every real
download is split across hundreds of segments, so per-packet matching can
tell you that some bytes looked interesting, never what the file **is**.

This closes that gap. It follows a transfer across packets, buffers the body,
and identifies the finished object:

1. a flow is picked up when a response looks like a file transfer
2. its body is buffered, bounded, up to the scan limit
3. at the end of the body the object is hashed (SHA-256) and looked up
4. the same buffer is swept for byte patterns a per-packet scanner would
   have missed across a segment boundary

**What it does not claim.** It reads what it can see. TLS is opaque to it, and
on a modern network most downloads are TLS — so it inspects plaintext
transfers and nothing else. That limit is reported rather than hidden: the
console's Coverage panel shows how many bytes went past encrypted, beside how
many were actually inspected. It is not an endpoint anti-virus; there is no
unpacker, no emulator, and no heuristics beyond the four steps above.

**Coverage is not the same thing as "enabled".** Scanning is set per segment
(`malware_scan` under each `[vlan:…]`), so the engine can be on, blocking,
with a loaded database, over a network where no segment has it switched on —
inspecting nothing. The console used to report that appliance as *ON*. It now
reports the AND of the two: `5 / 6 segments covered`, the names of the ones
that are not, and **NO COVERAGE** in the same red as *off* when the count is
zero, because that is what it is.

Traffic that matches no configured segment is not scanned either — the flag
is read from the segment, so there is nowhere to read it from. The API says
so explicitly (`"unmatched_scanned": false`) rather than leaving it to be
discovered.

Memory is bounded by construction. Reassembly is attacker-reachable
allocation, so there is no malloc per flow: the flow table is a fixed array,
each slot owns a fixed buffer carved from one arena at startup, and when they
are all busy new flows are **not tracked** (and counted) rather than evicting
one that is mid-scan. A full table degrades to the per-packet scanner, which
is the direction that fails safe.

```ini
[malware]
enabled       = yes
block         = no        # detect-only: report, never drop
max_object_kb = 512       # objects larger than this are hashed that far
database      = /etc/firex/malware.db
```

It **ships in detect-only mode on purpose**. A scanner that starts dropping
traffic the first time it is switched on, before anyone has seen what it
matches on this network, is a scanner that gets switched off again. Watch the
Detections list for a few days, then set `block = yes` — or flip it from
*Security → Malware* without a restart.

**What `block = yes` actually does, precisely.** A whole-object verdict
arrives when the last byte of the body has been seen — by which point that
byte, and every byte before it, has already been forwarded. So `block` does
not prevent the download: it **resets the flow on the match**, records the
detection, and feeds the source into the auto-response scorer so the host is
quarantined for its next attempt. Anything that claims to stop a file it only
recognises at the end is describing something it cannot do. Blocking *before*
delivery is the job of the layers that decide on the request rather than the
response — the reputation feeds and the per-packet signatures, both of which
run first.

**Objects larger than `max_object_kb` get no hash verdict at all.** The
database holds whole-file digests; a digest of the first 512 KB of a 4 MB
file cannot match one, so comparing it would be a guaranteed false negative
dressed up as a check. Those objects are counted separately in *Coverage* as
**not hash-inspected** — byte patterns still run over what was buffered,
because a pattern found in a prefix really is found.

The database is one record per line, `<sha256> <severity 1-4> <name>`. A
malformed row is skipped and counted; one bad line in a feed does not cost
every line after it. A file that cannot be read leaves the **previous**
database loaded, for the same reason the reputation feeds keep a stale list
rather than emptying themselves.

`config/malware.db` ships empty. The scanner is not idle without it: the
built-in byte patterns still run, and they include the EICAR test string —
which is not malware, and that is the point. A security feature nobody can
test is a security feature nobody should trust:

```bash
curl http://<any plaintext host>/eicar.com     # should be detected
```

## Air gap

"Unplug the cable" is a policy, not a product: somebody has to unplug it, at
the right time, and plug it back for exactly as long as the work takes. On a
network operated by people, that holds for about a week.

FireX enforces the same intent in the datapath, in six degrees, so the right
one can be chosen for the site instead of the only one:

| Mode | What crosses the boundary |
|---|---|
| `connected` | everything; nothing is enforced here |
| `scheduled` | nothing, except inside named transfer windows |
| `inbound-only` | a data diode pointing **in**: may receive, may never send |
| `outbound-only` | the diode reversed: may send, no session opened from outside |
| `isolated` | nothing, either direction |
| `manual` | isolated, **and** the appliance fetches nothing of its own |

What each mode does to each class of traffic. The middle column — the
appliance's *own* outbound traffic — is what decides whether a mode is really
an air gap or just a strict firewall:

| Mode | User traffic | Appliance fetches | Time source |
|---|---|---|---|
| `connected` | both directions | yes | NTP |
| `scheduled` | inside windows | inside windows | NTP |
| `inbound-only` | inbound only | no — fetching means talking out | NTP inbound |
| `outbound-only` | outbound only | yes | NTP |
| `isolated` | none | no | RTC only |
| `manual` | none | no | RTC, or set by an operator |

The distinction that matters in practice is the last row. An appliance that
blocks all user traffic but still reaches out for its own signature updates
is not air-gapped — it is a firewall with one sanctioned tunnel through it,
and that tunnel is the most valuable target on the network. `manual` closes
it; signatures and update bundles are carried in and installed by hand.

**Where that column is enforced.** Transit traffic is judged in the datapath
by `airgap_verdict()`. The appliance's *own* connections are judged at each
subsystem, through one gate in `include/egress.h` that `firexd` binds to the
air gap at startup:

| Subsystem | What it would reach out for |
|---|---|
| `feeds` | reputation and blocklist refreshes (`file://` lists still load) |
| `telemetry` | syslog and NetFlow to your collectors |
| `ha` | configuration push to the standby node — receiving one is inbound, and is not gated |
| `gwmon` | gateway reachability probes |

Update bundles and packages need no gate: they are installed from a local
file and never fetched, which is why `manual` can work at all.

Each subsystem's refusals are counted separately and shown on the *Air gap*
page. **A row reading zero while the gap is shut means that subsystem is not
being gated** — which is the state this product shipped in before
`tools/preflight.sh` and `make test-egress` started checking for it. The
function existed, the documentation promised it, five tests exercised it
directly, and nothing in the product ever called it.

**`manual` and `scheduled` cannot both be satisfied.** `manual` fetches no
time of its own, so the clock never becomes disciplined, so
`require_time_sync` fails every window shut — for ever, with nothing to say
why. The two features cancel out, so the combination is **refused** at
validation with the three ways out named in the message, rather than accepted
and silently cutting a site off.

```ini
[airgap]
mode              = connected
require_time_sync = yes
# window = name,days,HH:MM,HH:MM,inbound,outbound
window            = nightly-sync,-MTWTF-,02:00,04:00,1,1
```

`days` is a seven-character mask starting Sunday, so it reads the way a
weekly schedule is drawn: `-MTWTF-` is the working week. A window whose end
is before its start **wraps midnight** and belongs to the day it *starts* on,
so an overnight window runs into the next morning rather than quietly
stopping at the weekend.

`require_time_sync` makes a scheduled gap **fail shut** when the clock is not
disciplined. A schedule is decided entirely by local time, so an appliance
that boots with a bad clock would otherwise pick a window at random.

**What this does not claim.** Enforcement is at the packet layer, so it is as
good as the appliance is. A true physical gap is a property of the cable, and
no setting here substitutes for one where the threat model demands it. What
this gives is an enforced, scheduled approximation that cannot be forgotten
about, plus a record of every crossing it refused.

## Interfaces

*Network → Interfaces* reports what the **kernel** believes, not what the
configuration asked for. Those two disagree exactly when something is wrong —
a port configured for a gigabit that negotiated 100, a link administratively
up with no carrier — and that disagreement is the most useful thing an
interface page can show. Playing the configuration back tells an operator
nothing they did not already type.

Each row carries link state, negotiated speed and duplex, address, MAC, MTU,
the security zone the port belongs to, and the error and drop counters. A
port reading **No carrier** is configured and enabled with nothing plugged
in — a cable, not a configuration fault, and the page says so.

Bringing a link down from the console is refused for a port in `ZONE_MGMT`:
it is the most effective way to lock yourself out of an appliance, and it
cannot be undone from the page that just disappeared.

## Admin console

Served at **`/ui`** on a listener **of its own**, behind a login.

That separation is load-bearing. The block page has to face the untrusted
segments — being redirected to it is what a quarantined host experiences —
while the console must never. One listener meant one bind and one exposure: a
host on GUEST could reach the login page of the appliance that was
quarantining it. So there are two sockets, and the daemon **refuses to
start** if they would resolve to the same one rather than quietly collapsing
back into a single port:

| Listener | Default | Binds to | Serves |
|---|---|---|---|
| Block page portal | `:8080` | every interface | the block page, `/override` |
| Administration console | `:8443` | the management zone's gateway | `/ui`, `/api/*` |

```ini
[console]
port = 8443
bind = mgmt      # an address, "mgmt" for the management zone, or "any"
```

A console path requested on the portal port is a `404`, and the portal is not
rendered on the console port — so neither listener can be used to learn what
the other is doing.

Each listener also caps how many connections it will serve at once
(`BP_MAX_CONNS`, 64). The counts are separate per listener on purpose: the
portal faces the segments the appliance is defending against, and a flood
there must not be able to take the management console down with it.

### TLS

The console terminates TLS, and does so **by default** — `tls = no` in
`[console]` is the only way to turn it off, for a deployment where something
in front of the appliance already terminates it.

The certificate is **not in the image**. A certificate built into an image is
a private key that every appliance built from that image shares, which is a
key an attacker already has — the same reason `/etc/ssh` host keys are
generated on first boot rather than baked in. FireX generates a self-signed
one on its first start, with a `subjectAltName` (browsers ignore `CN`
entirely and reject a certificate without one), `CA:FALSE`, `serverAuth`, and
a 3072-bit key.

Its SHA-256 fingerprint is printed at boot and shown on the *System* page:

```
[FireX]   TLS enabled; certificate fingerprint
[FireX]   SHA-256 89:D7:9D:A7:AA:08:D2:A2:D9:3D:F4:…
[FireX]   compare that on the browser's first-visit warning before accepting it
```

Compare it once and the identity stays the same across restarts and updates.
Point `tls_cert` and `tls_key` at your own PEM files to use a certificate
signed by an internal CA, which removes the warning entirely.

The session cookie carries `Secure` and the response carries HSTS **only when
TLS is actually on** — a `Secure` cookie sent over plain HTTP is discarded by
the browser, so hard-coding it would break every login on a cleartext console
with no error anywhere to explain it, and an HSTS header from a cleartext
console pins the browser to an origin that does not answer.

The desktop console discovers which it is per connection: it attempts a TLS
handshake and treats a failure as "this listener is plain HTTP". So an
operator who switches TLS off does not then have to find a matching switch on
the console, and a daemon restarted with the setting changed underneath an
open console keeps working.

### Navigation

The navigation
is grouped the way an operator works — what is happening, then the network,
then what is defending it, then the box itself:

| Group | Pages |
|---|---|
| **Monitor** | Dashboard, Events, Diagnostics |
| **Network** | Interfaces, Segmentation, WAN, VPN |
| **Security** | Malware, Air gap, Threat, Policy, Portal |
| **Appliance** | Configuration, Audit, System |

Colour means status and nothing else: red is a fault, amber a warning, green
healthy, and the brand colour is reserved for the current selection and the
primary action. There are **no emoji** anywhere in it — they are drawn by the
operating system, so the same appliance looks different on every workstation
and renders a dotted box on the hardened ones with no colour font. The icons
are an inline SVG set defined once in the page, and `tools/preflight.sh`
fails the build if an emoji reappears — in the web console *and* in the
desktop one, which had thirty-eight of them and was never checked because
they were written as C escapes (`"\xf0\x9f\x9b\xa1"`) that a byte scan of
the source cannot see. The guard now reads the built binaries.

Two things the shell reports that no page can: whether the session arrived
**encrypted**, and whether anything applied is still only in memory
(**unsaved**). Both were invisible, and both matter — see *Running and saved*
below.

Reads need a session; writes need a session with the `admin` role **and** a
matching `X-FireX-CSRF` header, so a cookie on its own is never enough to
act. A `viewer` account reads every endpoint and is refused on all of them.

```
GET  /api/vlans              VLANs, ports, zone matrix, counters
GET  /api/interfaces         every link as the kernel reports it
GET  /api/malware            scanner state, per-segment coverage, detections
GET  /api/airgap             boundary mode, windows, per-subsystem refusals
GET  /api/audit              the administrative trail           (admin only)
POST /api/audit/verify       recompute the hash chain           (admin + CSRF)
GET  /api/system             version, TLS state and fingerprint, unsaved count
GET  /api/accounts           who exists, and which passwords are still shipped
POST /api/accounts/password  set a console or Linux password  (admin + CSRF)
POST /api/malware/mode       enable/disable, block or detect-only (admin + CSRF)
POST /api/airgap/mode        change the boundary mode          (admin + CSRF)
POST /api/interfaces/<if>/admin   bring a link up or down      (admin + CSRF)
POST /api/config/apply       re-provision the network          (admin + CSRF)
```

Sessions live in memory only, so a restart signs everyone out — there is no
session store on disk to steal. Changing a password drops every session that
account holds, including the one that changed it.

### Running and saved

The console applies a change **at once** and writes it to the configuration
file only on *Save revision*. That is the right model — it is how an operator
tries something and backs out of it — but it was previously silent, so
isolating an appliance and rebooting it brought it back `connected` with
nothing having warned anyone.

Now the endpoints that change running state say so:

```json
{ "ok": true, "mode": "isolated", "persisted": false,
  "hint": "in effect now; POST /api/config/save or this appliance
           returns to 'connected' when it restarts" }
```

…the hint names the mode **read from the file on disk**, not from memory, and
the shell carries an *n unsaved changes* badge until a revision is saved. A
link brought up or down through `/api/interfaces/<if>/admin` reports
`persisted: false` too, and offers no way to save it: that is an ioctl on a
kernel interface, not a configuration setting.

## Audit trail

`logger.c` records traffic. The audit trail records the **operators** — and
those are different questions with different readers. After an incident
nobody asks which packets were dropped on Tuesday; they ask who turned the
air gap off on Tuesday, from where, and whether it was supposed to be them.

Before this existed, that answer was five `fprintf(stderr)` calls reaching
journald: not queryable from the console, rotated on someone else's schedule,
and writable by anyone who reached root on the box — which is exactly the
person an audit trail exists to record.

Every administrative action is recorded with the actor, the source address,
the outcome, and enough detail to be useful on its own:

```
7   2026-10-30T01:15:26Z  admin  127.0.0.1  airgap.mode  isolated  ok  boundary changed from connected to isolated
8   2026-10-30T01:15:44Z  bob    10.0.9.14  authz.deny   POST      denied  bob is read-only and attempted a write
```

Refusals are recorded as well as successes. A sign-in failure records *why* —
wrong password, throttled, unknown account — while the HTTP response stays
deliberately identical for all three, so the detail an investigator needs
exists where the client cannot read it. Passwords never appear, in any
branch.

**Tamper evidence.** Each record carries a SHA-256 over the previous record's
hash and its own text, so the file is a chain:

```
record 412 does not follow record 411 -- it was edited, or a record
before it was removed
```

Deleting a line, editing a field, reordering two, or appending one by hand
all break it, and `POST /api/audit/verify` names the first record that no
longer follows. This does **not** make the trail unalterable — nothing on a
box an attacker owns can be. It turns a silent deletion into a visible gap,
which is the property that is actually useful afterwards.

Fields are tab-separated and every value is escaped, so a VLAN named
`guest\t9\t…\troot\t…\tairgap.mode\tconnected\tok\tdisabled` writes one
record, not two. Log injection into the audit trail would otherwise forge
entries that *verify*, because the forged text would sit inside the hashed
body of a record the appliance wrote itself.

Records reach the ring buffer before the file, so a full disk costs the
`/api/audit` page nothing — and a trail that is not reaching disk says so, in
red, on that page.

## Tests

```bash
make test          # rule engine           (no root, no network)
make test-seg      # segmentation/zones    (no root, no network)
make test-config   # config spine and auth (no root, no network)
make test-phase8   # updates, A/B slots, boot splash
make test-phase9   # malware, air gap, interfaces  (no root, no network)
make test-egress   # does the air gap gate the appliance's OWN traffic?
make test-tls      # console TLS, end to end against the real listener
make test-audit    # audit recording, log injection, tamper evidence
make test-list     # which suites exist, generated, not written down
make test-gui      # desktop console API client
sudo make test-xdp # XDP                   (loads BPF, builds a veth pair)
make test-all      # everything above, plus phases 2-7
```

`make test-list` prints the suites, read out of the Makefile itself — a count
written down in prose drifts the moment a suite is added. Everything except
`test-xdp` runs without root and without touching the network: packets are
synthesised in memory, and the two suites that do open sockets (`test-tls`,
`test-egress`) bind loopback on ports the daemon does not use.

**`test-egress` is written the way it is on purpose.** It never calls the air
gap's own functions. It binds a counting predicate and then drives
`feed_fetch()`, `gwmon_ping()`, `ha_push_config()` and `telemetry_log()` the
way the daemon drives them, asserting that each one **asked**. The previous
suite called `airgap_network_permitted()` directly, passed every assertion,
and proved nothing: no code in the product called that function at all. A
test that calls the gate proves the gate works; only a test that calls
`feed_fetch()` proves `feeds.c` knows the gate exists. `make image-check` runs
`tools/preflight.sh`, which checks the things a build cannot discover until
ten minutes in — artwork, fonts matched by their internal name, unit files,
and that the shipped configuration and the kernel command line agree about
what the interfaces are called.

## Building it into an OS

FireX ships a bootable appliance image builder. The result is a hybrid
**BIOS + UEFI** raw disk image you can `dd` to a USB stick or SSD, or boot
under QEMU.

```bash
make deps-image      # debootstrap, parted, grub, qemu, ovmf
make                 # build firexd first
make image           # -> build/firex.img   (needs root, ~200MB download)
make qemu            # boot it, serial console in your terminal
```

The image is GPT with five partitions, so the same image boots on legacy BIOS
and UEFI machines without rebuilding, and can update itself in place:

| # | Size | What |
|---|---|---|
| 1 | 1 MiB | BIOS boot, for GRUB on legacy machines |
| 2 | 128 MiB | FAT32 ESP, for UEFI |
| 3 | ~3.5 GiB | root slot **A** (`firex-root-a`) |
| 4 | ~3.5 GiB | root slot **B** (`firex-root-b`) |
| 5 | rest | shared data (`firex-data`) — config, state, logs |

An update is written to the slot that is *not* running and booted once on
trial; a slot that fails to come up is marked bad and the other one is booted
instead. `/etc/firex` is a symlink into the data partition, so configuration
and state survive an update of either slot.

Inside it: a minimal Ubuntu base, a generic kernel, `iptables`/`ipset`/
`dnsmasq`/`conntrack`, `libnetfilter_queue` and `libbpf`, `firexd` in
`/usr/local/bin`, your config in `/etc/firex`, and both systemd units enabled.

`grub.cfg` is generated by `src/slots.c`, not by `update-grub` — it has to
name both slots and their state, which `update-grub` knows nothing about. So
every kernel argument that matters has to be on that generated line;
`/etc/default/grub` is present but nothing here reads it.

- `net.ifnames=0 biosdevname=0` — keeps interfaces named `eth0`, `eth1`, so
  the names in `firex.conf` mean what they say. With predictable naming on
  they come up as `enp0s3` and `enp0s8`, every `[port:ethN]` stanza misses,
  and the appliance boots perfectly while segmenting nothing — no error
  anywhere, because a port that is not in the configuration is not a fault,
  it is just a port nobody mentioned. `tools/preflight.sh` checks that the
  config and the kernel line still agree about this.
- `console=ttyS0,115200n8 console=tty0` — the appliance is usable headless
  and over a serial console. `tty0` is named **last** deliberately: the
  kernel points `/dev/console` at the final `console=`, and Plymouth follows
  `/dev/console`.
- `plymouth.ignore-serial-consoles` — ordering alone is not enough. Plymouth
  also scans for serial consoles independently and, finding `ttyS0`, gives up
  on the splash and prints the boot log instead. Without this the appliance
  shows a screen of systemd lines where the logo should be, on a machine
  whose framebuffer was working the whole time.
- `quiet splash` — the graphical boot screen. `FIREX_BOOT_SPLASH=0` drops all
  three of the splash arguments and boots verbose instead.

The builder prints the shipped credentials at the end. They default to
`root`/`root` and `admin`/`admin` (see *Logging in*); set
`FIREX_ROOT_PASSWORD` and `FIREX_ADMIN_PASSWORD` to choose your own.

Before it finishes it verifies the image can actually boot — that an initramfs
was produced and is a plausible size, that `grub.cfg` references it, that
`root=` is the filesystem's UUID rather than a build-host loop device, and
that the UEFI loader is in place. Any of those failing aborts the build rather
than handing you an image that panics on first boot.

### VirtualBox

VirtualBox cannot boot a raw `.img`, so convert it and build a VM around it:

```bash
sudo apt-get install -y virtualbox   # then log out and back in
make vbox                            # or: make vbox-efi
VBoxManage startvm FireX --type headless
socat - UNIX-CONNECT:build/FireX-console.sock
```

The script converts the image to a dynamically-sized VDI, creates the VM, and
wires two adapters:

| NIC | Mode | Guest | Notes |
|---|---|---|---|
| 1 | NAT | `eth0` (WAN) | DHCP + outbound internet, host forwards for the portal and SSH |
| 2 | Internal network `firex-lan` | `eth1` (LAN) | **Promiscuous `allow-all`** |

That promiscuous setting is the one easy thing to get wrong. By default a
VirtualBox adapter drops frames not addressed to its own MAC, so a firewall
sitting on a trunk would see almost nothing — no VLAN-tagged traffic, no
frames destined for other hosts. Without it the segmentation engine looks
broken when it is merely blind.

Attach other VMs to the same internal network (`firex-lan`) to put them behind
the appliance.

Reach it from the host at **http://127.0.0.1:18443/ui** (console),
**http://127.0.0.1:18080/** (block page) and `ssh -p 12222 root@127.0.0.1`.

### Image size

A stock build allocates 8 GB for the whole disk, of which a root slot is
about 1.2 GB. Most of a slot is not content:

| Item | Size |
|---|---|
| `linux-modules-generic` | ~159 MB (drivers for every device Ubuntu supports) |
| apt package index | ~150-200 MB |
| initramfs (`MODULES=most`) | ~60-100 MB |
| Ubuntu base: systemd, apt, dpkg, perl | ~150 MB |
| docs, man pages, translations | ~50 MB |

Real content is nearer 600 MB; the rest is blocks that deleted files left
allocated in the host file. `make shrink` fixes both halves:

```bash
make shrink      # trims content, then collapses the sparse file
```

It removes the apt index (`apt-get clean` does not), documentation, man pages
and non-English translations, and leaves a dpkg exclude rule so later
`apt install` runs on the appliance do not put them back. Then it zero-fills
the free space and punches holes, which is what actually reclaims disk.

It also clears `/etc/machine-id` and the SSH host keys. Both regenerate on
first boot — without that, every appliance flashed from one image would share
a machine ID and present the same SSH host key.

New builds get all of this automatically. The default disk is 8 GB,
because two root slots and a data partition have to fit; `FIREX_IMAGE_SIZE=12G` makes it bigger.

For genuinely small images — the 10-50 MB that OpenWrt-class systems reach —
a Debian base is the wrong starting point. That needs Buildroot or Alpine:
musl, BusyBox, and a kernel built with only the drivers for your hardware.
The sysvinit scripts under `board/rootfs_overlay/etc/init.d/` are already
written for that target. For reference, pfSense and OPNsense are 1-2 GB
installed, so this is not far off them.

### Logging in

The appliance ships with two accounts, both guessable on purpose:

| account | password | role |
|---|---|---|
| `root`  | `root`  | uid 0 |
| `admin` | `admin` | in `sudo` |

Each pair works in **both** places, because each is enrolled in both databases:

- the **Linux** account — SSH, and the shell behind the serial menu
- the **FireX** account — `http://<appliance>:8443/ui` and the serial menu

Two databases sit behind one appliance and they are invisible from the
outside, so a credential that opened SSH and then failed on the web console
is the kind of thing that costs an afternoon. Both are seeded at build time
to stop that happening.

This is a known password on a known port. It is a deliberate trade: an
appliance you cannot reach is an appliance you reinstall, and a generated
password printed once into a terminal scrollback is a password you have
already lost. The product says so rather than hiding it — the web console
shows a banner on every page and the serial menu says it at login, both
until the password is actually changed. Neither can be cleared by setting
the password back to the default; that is refused.

Change them before the appliance faces anything you do not control:

- **web console** — *System → Accounts*, which changes either database
- **serial menu** — option 4
- **shell** — `passwd root`, and
  `firexd --passwd admin --users /etc/firex/users`

Build with your own instead:

```bash
sudo env FIREX_ROOT_PASSWORD=... FIREX_ADMIN_PASSWORD=... tools/build-image.sh
```

Password login over SSH is **on** by default, for both accounts, so the
credentials above work from the first boot. `FIREX_SSH_ROOT_PASSWORD=0`
restores `PermitRootLogin prohibit-password`, leaving `admin` as the SSH
account and root to the console. On anything exposed, drop a public key into
`/root/.ssh/authorized_keys` and set `PasswordAuthentication no` in
`/etc/ssh/sshd_config.d/10-firex.conf`.

SSH host keys are **not** in the image. They are generated on the appliance
on its first boot, by `firex-sshd-keygen.service`, so two appliances flashed
from one image never share an identity — a key they all share is a key an
attacker already has. This cannot be left to openssh's own postinst, which is
skipped when the package is installed into a chroot; without the unit, `sshd`
exits with *no hostkeys available* and burns its restart limit before the
appliance has finished booting.

### Writing to real hardware

```bash
sudo dd if=build/firex.img of=/dev/sdX bs=4M status=progress conv=fsync
```

**That destroys everything on the target.** Check `lsblk` first. On first
boot, edit `/etc/firex/firex.conf` for the machine's real interfaces — the
shipped config assumes `eth0` WAN and `eth1` as a trunk.

### Lab config

`config/firex-qemu.conf` is a two-interface version (WAN on `eth0`, a trunk on
`eth1` carrying CORP and GUEST) that matches what `run-qemu.sh` gives the VM.

```bash
firexd --dump -c config/firex-qemu.conf
```

### Running as a service

```bash
systemctl status firexd
journalctl -u firexd -f
firexd --dump -c /etc/firex/firex.conf    # review config, changes nothing
```

`firex-segmentation.service` runs first and loads `8021q`, `br_netfilter`,
`ip_set`, `nfnetlink_queue`, creates the quarantine ipset and sets
`FORWARD DROP`. `firexd.service` then provisions and starts the engine. Both
tear down cleanly on stop.

The rest of the units, and what each one exists to prevent:

| Unit | Why it exists |
|---|---|
| `firex-rootfs-rw.service` | The kernel is handed `ro` so the root can be checked, and this image deliberately has no `/` line in fstab — the label differs per slot. Without this nothing ever remounts it, and the appliance runs its whole life read-only: sshd cannot write host keys, logind cannot write state, and X cannot open its log. |
| `firex-sshd-keygen.service` | Per-appliance SSH host keys on first boot. |
| `firex-mgmt-link.service` | Brings every physical link up, and asks DHCP for an address on the first one with carrier **only when nothing has an address anywhere** — so it cannot fight the daemon for an interface. Without it a factory appliance boots with every link down and nothing can reach it. |
| `firex-gui.service` | The desktop console on tty1. Conflicts with `getty@tty1` so the two do not take turns owning the screen, and orders after `plymouth-quit-wait` so X is not fighting Plymouth for the framebuffer. |
| `firex-console.service` | The serial menu on `ttyS0`. Has no start limit: the serial port is the last way into an appliance whose screen or network has failed, so it must never permanently give up on it. |
| `firex-boot-check` / `firex-confirm` | A/B accounting — one spends a boot attempt, the other marks the running slot good once `firexd` is actually up. |

### Other targets

`board/rootfs_overlay/etc/init.d/S15segmentation` and `S20firex` are
sysvinit/BusyBox equivalents, for overlaying onto a Buildroot rootfs if you
want something smaller than a Debian base. The overlay is laid down verbatim,
so the same tree serves both.

**Not included:** an installer — the image is written whole, not installed
from. A/B update slots and signed update bundles *are* included; see
`docs/UPDATES-AND-PACKAGES.md`.

## Layout

```
include/       headers
src/           engine, DPI, rate limiting, NFQUEUE, XDP loader,
               VLAN segmentation, WAN/NAT/DHCP, block page, console API,
               threat detection (ids, feeds, malware, response),
               air gap, interface inventory, A/B slots and updates
src/gui/       GTK4 pages for the desktop console
src/webui/     web console assets (embedded into the binary at build)
xdp/           eBPF kernel program + the ABI it shares with userspace
tests/         one suite per area; `make test-list` enumerates them
board/         rootfs overlay, systemd units, boot artwork and themes
config/        firex.conf, rules.conf, rules.ids, malware.db
tools/         image builder, preflight, splash generator, asset embedder
docs/          update/package design, pfSense parity roadmap
```

## Not built

Stated plainly, and kept honest — everything that used to be listed here and
has since been built has been taken off the list:

- **TLS interception** for branded HTTPS block pages, and for scanning
  encrypted downloads. Both need a MITM proxy with a CA pushed to managed
  endpoints; neither is built here, and the malware scanner reports how much
  traffic went past it unread rather than implying otherwise.
- **An installer.** The image is written whole with `dd`, not installed from.
- **A packaged signature feed.** `config/malware.db` ships empty on purpose:
  hashes are specific to whatever threat intelligence a site subscribes to,
  and shipping a stale handful would suggest coverage that is not there.
- **Clustering beyond two nodes.** HA is active/passive VRRP, not a fabric.
- **NAC.** No 802.1X supplicant handling, no MAB, no posture assessment, and
  no dynamic VLAN assignment from a policy server. Port security here is
  static: a port carries the VLANs its `[port:…]` stanza allows, and a tag it
  is not allowed to carry is a violation. That is enforcement, but it is not
  admission control — nothing authenticates the *device* before the port
  starts forwarding.
- **A directory bind.** There is no LDAP or Kerberos client, so the appliance
  never joins or queries Active Directory. Portal users authenticate against
  **RADIUS** (a complete RFC 2865 PAP client, `src/portal.c`), which is the
  usual way to reach AD — through NPS or FreeRADIUS in front of it — but that
  is a hop, not an integration: no group membership, no user-to-IP mapping,
  and no identity on a firewall rule.
- **URL filtering beyond HTTP.** Domain blocking reads the **`Host:` header of
  a plaintext HTTP request** (`firex_extract_http_host()`), so it does not see
  an HTTPS request at all — the TLS `ClientHello` SNI is not parsed. On a
  modern network that is most of the traffic. There is also no URL *path*
  matching and no category database; the lists are IP and domain blocklists
  from `[feed:…]`.
- **Application control.** `RULE_DPI_REGEX` and `RULE_DPI_CONTENT` match bytes,
  and `src/ids.c` matches signatures. Neither is App-ID: there is no
  application decoder set and nothing identifies a protocol that is not on its
  usual port.
- **GeoIP.** `RULE_COUNTRY` is in the rule-type enum and has **no matcher**, so
  a rule of that type never fires. It is a placeholder, not a feature.

## Desktop console

The appliance brings up its own screen: a sign-in page, and behind it the
GTK4 console. It is a **client of the running daemon**, over the same HTTP
API the web console uses — so the GUI, the browser, SSH and the serial menu
are four views of one state rather than four opinions about it. Signing in
here is the same act as signing in at `http://<appliance>:8443/ui`, against
the same accounts, the same session table and the same throttle.

The sign-in screen also answers the question an operator standing in front
of an appliance actually has, which is *where is it*: every interface and
its address, the URL to browse to, the `ssh` line to type, and whether
`firexd` is up. "Run ifconfig" is not advice you can take from a login
prompt.

| Surface | Reaches it |
|---|---|
| Desktop console | the appliance's own monitor, or `firex-gui` |
| Web console | `http://<appliance>:8443/ui` |
| SSH | `ssh admin@<appliance>` |
| Serial menu | `ttyS0`, option 13 starts the desktop console |

After sign-in the **Appliance** page shows live daemon state: VLAN, port and
ACL counts, inter-VLAN decisions, tag violations, WAN links with their
reachability, and the schedule windows with which are open *right now* —
evaluated by the daemon against its own clock, not the GUI's.

The screen size is fixed. One value reaches GRUB's framebuffer, Plymouth,
Xorg and the console's own window, because setting it in only some of those
leaves the GUI letterboxed inside a frame of another shape:

```bash
sudo env FIREX_SCREEN=1280x800 tools/build-image.sh
```

`tools/to-virtualbox.sh` reads that back out of the image manifest and
offers the guest the matching mode. `FIREX_DESKTOP=0` leaves the whole X
stack out, which is the right choice for a headless box.

There is no desktop environment and no display manager: one X server, one
fullscreen window that cannot be closed, and a loop that restarts it if it
exits — with nothing behind it, a console that quits leaves a black screen
and no way back.

Run it by hand from anywhere:

```bash
firex-gui                      # on the appliance's own screen
firex-gui --check              # say why it would not start
firex-gui --help               # options; --size, --port, --screenshot
```

`--check` is the thing to run when the screen stays black. A console that
cannot start shows nothing and says nothing, so it reports each prerequisite
in turn: the binary, whether GTK resolves, `startx` and `Xorg`, whether there
is a framebuffer or DRM device to draw on, the Xorg config, whether anything
is listening on the console port, whether the unit is enabled, and whether a
getty is contending for the same VT. It exits non-zero on a failure, so it
scripts.

The appliance has no screenshot tool, so the console can capture itself —
`flamewall --screenshot shot.png` renders the screen and exits, for
documentation or a support ticket.

## Boot screen

The appliance boots to a graphical screen rather than a wall of kernel
messages: the flame mark, **FireX by Sumon**, the tagline, a progress bar
and **Made by Sumon Nath**. It is two pieces that have to agree.

- **GRUB** draws its menu over `board/splash/grub.png` through the theme in
  `board/grub/themes/firex/theme.txt`. The artwork puts the mark in the top
  third and leaves the band below for the menu, so moving one means
  regenerating the other.
- **Plymouth** takes over once the kernel starts, using the script theme in
  `board/plymouth/firex/`. It composites the pieces itself and scales them
  to the panel, so a 4K monitor and a 640x480 VESA fallback both come out
  deliberate.

Every step is guarded. A missing font, theme or video driver costs the
artwork and nothing else — the plain text menu is selected first and the
graphical one only replaces it if it loads. The serial console keeps
receiving kernel messages either way, and pressing `Esc` during boot shows
them on screen.

`FIREX_BOOT_SPLASH=0` leaves it out and boots verbose.

The PNGs under `board/splash/` are committed, so the image build needs
neither Pillow nor a font stack. Regenerate them after changing
`include/brand.h`:

```bash
make splash
```

Under VirtualBox the splash needs a framebuffer GRUB can hand to the
kernel, so `tools/to-virtualbox.sh` picks VBoxVGA for BIOS and VMSVGA for
EFI, with 32MB of VRAM. If your host ends up without one, the appliance
still boots — you just get text.

## White-labelling

`include/brand.h` is the only file to change: product name, vendor, tagline,
byline, support contacts, colour palette, logo, policy-ID prefixes. The block
page, console, daemon banner, boot splash and log lines all derive from it.

That claim used to be false. Nine files carried the vendor name literally —
including the `Description=` in `firexd.service`, which `systemctl status`
prints on every appliance — and nothing failed when a re-skin missed them.
It is now enforced rather than asserted:

- the web console reads the names from `/api/system` instead of having them
  in its markup
- the overlay uses `@BRAND_FULL@`-style placeholders that the image build
  fills from the header, and the build **fails** if one survives into the
  image
- the boot artwork and the GTK sign-in byline come from `BRAND_AUTHOR`
- `tools/preflight.sh` fails if the vendor string appears anywhere outside
  `brand.h` and generated files, if a placeholder has no substitution, or if
  `brand.h` is newer than the artwork generated from it

**An empty support contact means "no such route", not "render it anyway".**
The block page shows only the contacts that are actually configured — no
dead `mailto:`, no placeholder phone number, no link to a documentation site
that does not exist. A blocked user will try whatever button is in front of
them, so a button that goes nowhere is worse than no button.

```c
#define BRAND_SUPPORT_EMAIL    ""     /* omits the mailto button   */
#define BRAND_SUPPORT_URL      "https://..."   /* renders "Support" */
#define BRAND_SUPPORT_PHONE    ""     /* omits the tel: button     */
#define BRAND_DOC_URL          ""     /* omits the footer link     */
```

Preflight fails if **every** route is empty — a page telling someone to
contact support with no way to do it — and warns for each one that is still
a placeholder. `admin_contact` in the configuration overrides the brand email
per deployment, and is HTML-escaped before it reaches the page: operator-
supplied is not the same as trusted.

The boot artwork is generated from the same header, so a re-skin is
`make splash` followed by a rebuild. `BRAND_HOSTNAME` also names the theme
directory in both bootloaders; the build renames the Plymouth files to match
and registers the theme through `update-alternatives`, which is the
mechanism the initramfs hook actually reads. (`plymouth-set-default-theme`
is a convenience wrapper that current Ubuntu releases no longer ship, so
nothing here depends on it being present.)

Two traps are worth knowing before editing the splash, because both fail
**silently** and `tools/preflight.sh` now guards each one:

- Plymouth's script language is C-like and knows only the two C comment
  forms. A `#` line is a parse error — and the script plugin reports
  nothing: it logs *executing script file*, stops at the first `#`, and
  leaves a black screen behind a renderer that is working perfectly.
- GRUB matches a theme font by the name stored **inside** the `.pf2`, not by
  the file name. A name it cannot match renders the menu with no text at all
  and no error. Read it with `strings /usr/share/grub/unicode.pf2 | head`;
  do not guess.
