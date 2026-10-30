# FireX updates, A/B slots and packages

How a FireX appliance is updated, how it recovers when an update does not
work, and how add-on packages are signed and installed.

---

## 1. The trust root

Every update and every package is an Ed25519-signed bundle. An appliance
verifies against the keys listed in `/etc/firex/update-keys`, and only
those. There is no fallback, no "unsigned but warn" mode, and no way to
install a bundle from the console that skips the check.

Generate a signing pair on a build host:

```bash
make bundle-tool
./firex-bundle keygen --out firex-signing
```

That writes `firex-signing` (the private key, mode 0600) and
`firex-signing.pub` (one keyring line). **The private key never goes on an
appliance.** An appliance that can sign its own updates has no update
signing — it would accept anything it produced itself, and so would anyone
who reached its filesystem.

Build an image that trusts the key:

```bash
sudo env FIREX_UPDATE_KEY="$PWD/firex-signing.pub" tools/build-image.sh
```

Note the `sudo env` form. Writing `FIREX_UPDATE_KEY=... sudo tools/...`
assigns the variable in your shell, and sudo's `env_reset` then drops it
before the script runs — the build would quietly produce an image that
trusts no key at all. Letting `env` do the assignment as root avoids the
question entirely.

Without `FIREX_UPDATE_KEY` the image still boots, with an empty keyring and
a comment explaining how to fill it. Every bundle offered to it is refused.
That is the intended default: an appliance that cannot be updated is better
than one that can be updated by anyone.

---

## 2. What a bundle is

A readable header followed by a raw payload:

```
FIREXUP1
kind: image
name: firex
version: 3.1.0
build: 2026-10-28T09:13:46Z
arch: x86_64
size: 419430400
sha256: a797265b22b9fd9e67a003be6dda0409c91631a0751c24f52bb88ac3d10a1d27
requires: 3.0.0
description: quarterly maintenance release
signer: e1123e05ceb04376
signature: 8MjRe6VaS7siFQceiHCq8Tkk...
%%
<payload bytes>
```

`head -14 bundle.fxu` shows an operator what they are about to install
before anything is verified or written.

**The signature does not cover the header text.** It covers a canonical
string rebuilt from the parsed fields:

```
firex-update-v1
kind=image
name=firex
version=3.1.0
build=2026-10-28T09:13:46Z
arch=x86_64
size=419430400
sha256=a797265b...
requires=3.0.0
description=quarterly maintenance release
```

Signing the canonical form rather than the raw header means reordering
lines, changing spacing or adding comments cannot move bytes in or out of
what was signed. The payload is bound to the signature through its
SHA-256, which is checked separately against the actual bytes. Both checks
must pass. A header that sets the same key twice is rejected outright
rather than resolved last-wins.

Verification refuses, with a reason, when:

| condition | message |
|---|---|
| payload byte changed | `payload digest ... does not match the signed ...` |
| any header field edited | `the signature does not match the bundle metadata` |
| payload truncated or extended | `payload is N bytes, the header claims M` |
| signer not in the keyring | `signed by unknown key <id>` |
| keyring empty | `no trusted keys are configured; refusing the bundle` |
| duplicate header key | `the header sets 'version' twice` |
| running version too old | `needs 3.0.0 or newer; this system runs 2.9.0` |

Build and check a bundle:

```bash
./firex-bundle sign --in rootfs.img --out firex-3.1.0.fxu \
    --key firex-signing --version 3.1.0 --requires 3.0.0 \
    --description "quarterly maintenance release"

./firex-bundle show   firex-3.1.0.fxu                       # claims only
./firex-bundle verify firex-3.1.0.fxu --keyring firex-signing.pub
```

On the appliance:

```bash
firexd --verify /var/tmp/firex-3.1.0.fxu
```

---

## 3. A/B slots

The disk carries two root filesystems and one data partition:

| part | label | holds |
|---|---|---|
| p1 | — | `bios_grub`, so one image boots BIOS and UEFI |
| p2 | `FIREX-ESP` | the ESP and the single `grub.cfg` |
| p3 | `firex-root-a` | root slot A |
| p4 | `firex-root-b` | root slot B |
| p5 | `firex-data` | `/etc/firex` and `/var/lib/firex` |

Configuration lives on the data partition, and `/etc/firex` and
`/var/lib/firex` are symlinks into it. Both slots therefore see the same
configuration. If configuration lived in a root slot, an update would
either lose it or have to copy it across, and a rollback would silently
take the configuration back in time along with the software.

`/etc/fstab` has no entry for `/`. Its label depends on which slot booted,
and the kernel already knows which from `root=LABEL=...` on its command
line; naming one of them in fstab would mount the wrong root after an
update.

### The state machine

Each slot is `unused`, `pending`, `good` or `bad`.

```
         install into the spare slot
  good ───────────────────────────────► pending (3 attempts)
                                            │
          firexd started  ──────────────────┤──────────────► good
                                            │
          3 boots, never confirmed ─────────┴──────────────► bad
                                                              │
                                   next boot ◄────────────────┘
                                   returns to the good slot
```

- `firex-boot-check.service` runs before `firexd` and spends one attempt.
- `firex-confirm.service` runs after `firexd` is active, waits 30 seconds
  for it to fail noisily if it is going to, and clears the pending state.
- When the attempts run out, `firexd --boot-attempt` exits 3. The script
  then **rewrites `grub.cfg` before rebooting** — without that the
  bootloader would keep selecting the slot that just failed.

The running slot is never written to and never erased. That is the whole
safety property: an update that does not reach a working `firexd` cannot
keep the appliance off the network.

### grub.cfg

`update-grub` is deliberately not used. It generates entries for the root
it probes and knows nothing about the second slot. `firexd --write-grub`
renders the config instead, from the same `slots.conf` the appliance acts
on, so the entries the bootloader offers and the state the appliance
believes cannot drift apart. The preferred slot is always listed first and
`set default=0` selects it.

### Operating it

```bash
firexd --slots                     # both slots, state, and the grub.cfg
firexd --write-grub /boot/grub/grub.cfg
firexd --confirm-boot              # this slot works; stop counting
```

Installing and rolling back are console menu options 7 and 9.

---

## 4. Packages

A package is an ordinary bundle with `kind: package` whose payload is a
gzipped tar. There is no second format and no second signature scheme —
whatever verifies a system image verifies a package. One trust root, one
verifier to get right.

```bash
tar -czf hello.tar.gz -C staging bin share
./firex-bundle sign --in hello.tar.gz --out hello.fxp --key firex-signing \
    --kind package --name hello --version 1.0.0
```

Installation never streams a tarball onto the filesystem. The archive is
listed first and the whole package is refused if anything is wrong:

1. **Every member name is checked** against a character whitelist
   (`A-Za-z0-9._-+/`) and walked component by component for `..`. One bad
   name refuses the package — a package that tried to write
   `../../etc/shadow` is not one to half-install. The whitelist is also
   what makes it safe to put member names in a shell command later.
2. **Symbolic and hard links are refused outright.** A link name can be
   innocent while its target points at `/etc`, and checking targets means
   parsing tar's verbose output, which is not reliably parseable for names
   containing spaces. Refusing links is a rule that can be enforced, so
   that is the rule.
3. Extraction uses `--no-same-owner` (a package cannot hand its files to
   another uid) and `--no-same-permissions` (it cannot ship a setuid-root
   binary and have the mode restored).

`..foo`, `foo..bar` and `a/..b/c` are ordinary names and are accepted;
rejecting them would be a bug in the other direction.

Records live in `/var/lib/firex/packages/<name>.pkg` and `<name>.files`.
Removal re-validates every path in the file list before touching it, so a
tampered record cannot reach outside the package root.

Console menu option 10 lists, installs and removes. An install always shows
its plan and asks before running it.

---

## 5. The serial console menu

`firexd --menu`, or `firex-console.service` on `ttyS0`.

It asks for a console password first, against the same user database the
web console uses (`/etc/firex/users`). When no users are configured it says
so loudly and opens anyway, so a half-built appliance cannot lock itself
out — that is a fallback, not a mode to ship in.

Enabling the menu masks `serial-getty@ttyS0`, so the serial port leads to
the menu rather than to a login shell. Build with `FIREX_CONSOLE_MENU=0` to
keep the plain getty instead.

Options marked `*` confirm before doing anything. Input is parsed strictly:
`13x` and `1 3` are both refused rather than read as `13`, because reading
a fumbled paste as "reboot" is exactly the failure a console menu must not
have.

---

## 6. What is not built

- **No delta updates.** A bundle carries a whole root filesystem.
- **No key rotation protocol.** Adding or retiring a signing key means
  editing `/etc/firex/update-keys`. There is no signed key-update bundle,
  so a compromised key is revoked by hand on each appliance.
- **No downgrade protection beyond `requires`.** A validly signed older
  bundle will install if its `requires` allows it. There is no monotonic
  version counter in hardware, so a physical attacker who can supply an old
  signed image can roll the software back.
- **No secure boot or measured boot.** The signature protects the update
  path, not the boot path. Nothing stops someone with physical access from
  writing a slot directly.
- **No package dependencies.** Packages are self-contained; nothing
  resolves or orders them.
- **No remote update trigger.** Updates are installed from the console or
  by hand, not pushed from a management server.
