#ifndef FIREX_UPDATE_H
#define FIREX_UPDATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Signed update bundles and A/B root slots.
 *
 * A bundle is a text header followed by a raw payload. The header is
 * readable with head(1) so an operator can see what they are about to
 * install before anything touches a disk:
 *
 *     FIREXUP1
 *     kind: image
 *     name: firex
 *     version: 3.1.0
 *     build: 2026-10-28T09:30:00Z
 *     arch: x86_64
 *     size: 419430400
 *     sha256: 9f86d0818...
 *     requires: 3.0.0
 *     description: quarterly maintenance release
 *     signer: 4a1fc0de9b27e551
 *     signature: <base64 Ed25519>
 *     %%
 *     <payload bytes>
 *
 * The signature does NOT cover the header text. It covers a canonical
 * string rebuilt from the parsed fields (see update_signed_material),
 * so reordering lines, changing spacing or adding comments cannot move
 * bytes in or out of what was signed. The payload is bound to that
 * signature through its SHA-256, which is verified separately. Both
 * checks must pass; either one alone proves nothing.
 */

#define UPD_MAGIC        "FIREXUP1"
#define UPD_SEP          "%%"
#define UPD_SIG_LEN      64        /* Ed25519 signature            */
#define UPD_KEY_LEN      32        /* Ed25519 public key           */
#define UPD_B64_LEN      128       /* room for either, base64 + NUL*/
#define UPD_SHA_HEX      65        /* 64 hex characters + NUL      */
#define UPD_KEYID_LEN    17        /* 16 hex characters + NUL      */
#define UPD_MAX_KEYS     8
#define UPD_MAX_HEADER   8192      /* refuse anything larger       */

/* A bundle carries either a whole root filesystem or one add-on package. */
typedef enum { UPD_KIND_IMAGE, UPD_KIND_PACKAGE } upd_kind_t;

typedef struct {
    upd_kind_t kind;
    char       name[64];
    char       version[32];
    char       build[32];
    char       arch[16];
    char       requires[32];        /* minimum running version, may be empty */
    char       description[160];
    char       sha256[UPD_SHA_HEX];
    char       signer[UPD_KEYID_LEN];
    char       signature[UPD_B64_LEN];
    uint64_t   size;                /* payload bytes                        */
    long       payload_offset;      /* where the payload starts in the file */
} upd_meta_t;

/* ── Trusted keys ───────────────────────────────────────────── */

typedef struct {
    unsigned char key[UPD_KEY_LEN];
    char          id[UPD_KEYID_LEN];
    char          comment[64];
} upd_key_t;

typedef struct {
    upd_key_t key[UPD_MAX_KEYS];
    int       count;
} upd_keyring_t;

/*
 * Loads a keyring file: one "<base64 key> <comment>" per line, blank
 * lines and # comments ignored. A malformed line is an error rather
 * than a skip -- a keyring that silently drops a key would quietly
 * reject the updates signed with it.
 */
int  upd_keyring_load(upd_keyring_t *r, const char *path, char *err, size_t errlen);
int  upd_keyring_add(upd_keyring_t *r, const unsigned char *pub, const char *comment);
const upd_key_t *upd_keyring_find(const upd_keyring_t *r, const char *keyid);

/* Key id: the first 8 bytes of SHA-256(public key), hex. */
void upd_key_id(const unsigned char *pub, char *out /* UPD_KEYID_LEN */);

/* Same, starting from the base64 form. Returns -1 if it does not decode. */
int  upd_keyid_from_b64(const char *pub_b64, char *out /* UPD_KEYID_LEN */);

/* ── Keys ───────────────────────────────────────────────────── */

/* Generates an Ed25519 pair. Both buffers need UPD_B64_LEN bytes. */
int  upd_keygen(char *priv_b64, char *pub_b64);

/* ── Creating and verifying bundles ─────────────────────────── */

/*
 * The exact bytes an Ed25519 signature is computed over. Returns the
 * length written, or -1 if the buffer is too small. Exposed so a test
 * can sign with its own code path and still agree with the verifier.
 */
int  upd_signed_material(const upd_meta_t *m, char *out, size_t outlen);

/*
 * Builds a bundle at out_path from payload_path. meta supplies kind,
 * name, version, build, arch, requires and description; size, sha256,
 * signer and signature are filled in here.
 */
int  upd_bundle_create(const char *payload_path, upd_meta_t *meta,
                       const char *priv_b64, const char *out_path,
                       char *err, size_t errlen);

/*
 * Parses the header only. Does no cryptography: use it to show an
 * operator what a bundle claims before deciding to verify it.
 */
int  upd_bundle_header(const char *path, upd_meta_t *meta,
                       char *err, size_t errlen);

/*
 * Full check: header well-formed, signer in the keyring, signature
 * valid over the canonical material, payload SHA-256 matches, and the
 * payload is exactly as long as the header claims. running_version may
 * be NULL to skip the "requires" check.
 */
int  upd_bundle_verify(const char *path, const upd_keyring_t *ring,
                       const char *running_version,
                       upd_meta_t *meta, char *err, size_t errlen);

/* Writes the verified payload to out_path. Verifies first. */
int  upd_bundle_extract(const char *path, const upd_keyring_t *ring,
                        const char *out_path, char *err, size_t errlen);

/* Compares dotted versions. <0, 0, >0 like strcmp. */
int  upd_version_cmp(const char *a, const char *b);

/* ── A/B root slots ─────────────────────────────────────────── */

typedef enum { SLOT_A = 0, SLOT_B = 1 } slot_id_t;

/*
 * UNUSED  nothing installed here yet
 * PENDING written but not yet proved to boot; tries_left counts down
 * GOOD    booted and confirmed by the running system
 * BAD     used up its attempts, or was marked bad by an operator
 */
typedef enum { SLOT_UNUSED, SLOT_PENDING, SLOT_GOOD, SLOT_BAD } slot_state_t;

#define SLOT_DEFAULT_TRIES 3

typedef struct {
    slot_state_t state;
    char         version[32];
    int          tries_left;
    char         label[32];        /* filesystem label, for the bootloader */
    uint64_t     installed;        /* unix time                            */
} slot_t;

typedef struct {
    slot_t    slot[2];
    slot_id_t running;   /* the slot that is executing now        */
    slot_id_t next;      /* what the bootloader should select     */
} slots_t;

void slots_init(slots_t *s);
int  slots_load(slots_t *s, const char *path, char *err, size_t errlen);
int  slots_save(const slots_t *s, const char *path, char *err, size_t errlen);

const char *slot_name(slot_id_t id);               /* "a" / "b"  */
const char *slot_state_name(slot_state_t st);

/* The slot an update should be written to: whichever is not running. */
slot_id_t   slots_target(const slots_t *s);

/*
 * Marks a slot freshly installed: PENDING with a full try budget, and
 * selected for the next boot. The running slot is never the target.
 * Returns -1 if id is the running slot.
 */
int  slots_begin_update(slots_t *s, slot_id_t id, const char *version, int tries);

/*
 * Called early in boot. Charges one attempt against the running slot
 * if it is PENDING. When the budget is gone the slot is marked BAD and
 * next is pointed back at the other slot if that one is usable.
 * Returns true when the caller should reboot into *next instead of
 * continuing here.
 */
bool slots_boot_attempt(slots_t *s);

/* The running slot booted far enough to be trusted. */
int  slots_confirm(slots_t *s);

/*
 * Operator-forced return to the other slot. Fails if that slot has
 * nothing usable in it -- a rollback to an empty slot is a brick.
 */
int  slots_rollback(slots_t *s, char *err, size_t errlen);

/*
 * Renders a complete grub.cfg for the two slots. Deterministic, so a
 * test can assert on it rather than on a booted machine.
 */
int  slots_grub_config(const slots_t *s, char *out, size_t outlen);

/*
 * Whether slots_grub_config() adds "quiet splash" to the kernel line.
 * On by default. Set it once at startup; it applies to every later
 * rewrite, including the one the boot-check fallback performs.
 */
void slots_set_splash(bool on);

/*
 * The video mode GRUB sets before the kernel starts, as "WxH". Also the
 * framebuffer Plymouth and Xorg inherit. Anything that is not WxH is
 * ignored rather than written out, since a malformed `set gfxmode=` line
 * costs the graphical menu entirely.
 */
void slots_set_gfxmode(const char *mode);

#endif /* FIREX_UPDATE_H */
