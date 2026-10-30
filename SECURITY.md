# Security

FireX is a network security appliance. It sits in the forwarding path, so a
defect here is not a crash in a side feature — it is a hole in the thing the
network is relying on.

## Reporting a vulnerability

Report privately, not as a public issue. Open a draft advisory under the
repository's **Security** tab, or mail <snath2973@gmail.com>.

Please include the appliance version (`firexd --version`), the configuration
that reproduces it with any secrets redacted, and what you observed against
what you expected. A packet capture of the failing exchange is worth more
than a description of it.

## What is in this repository, and what is not

**`firex-signing.pub` is here on purpose.** It is the public half of the
firmware signing key: the appliance uses it to verify that an update bundle
was signed by whoever built the image, and publishing it gives an attacker
nothing.

**`firex-signing` — the private half — is not here, and must never be.**
Anyone holding it can sign a bundle that a FireX appliance will accept,
install and boot. It is in `.gitignore` for that reason. Generate your own:

```bash
make bundle-tool
./firex-bundle keygen --out firex-signing
```

Keep the private key off the build machine's repository, back it up
somewhere a repository push cannot reach, and treat its disclosure the way
you would treat a code-signing certificate leak: rotate the key, rebuild the
image with the new public key baked in, and reflash every appliance that
trusted the old one, because an appliance already holding the old key will
keep accepting bundles signed with it.

## Default credentials

The image ships with `admin` / `admin` and forces a change on first sign-in.
If you build your own image, do not disable that prompt. SSH host keys are
deliberately **not** baked into the image — they are generated on first boot
by `firex-sshd-keygen.service`, because a key shared by every appliance is a
key an attacker already has.

## Scope

In scope: the packet engine, rule matching, the web and desktop consoles,
authentication and session handling, the captive portal, the update and
slot machinery, and the air-gap enforcement path.

Out of scope: findings that require physical access to an unlocked console,
denial of service by flooding a deliberately unmetered interface, and
anything the README's **Not built** section already says does not exist.
