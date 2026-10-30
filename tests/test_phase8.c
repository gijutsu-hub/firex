/*
 * Phase 8 tests: signed update bundles, A/B slots, package path safety,
 * console dispatch. No root, no network. Everything happens under a
 * temporary directory that is removed on the way out.
 *   make test-phase8
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "update.h"
#include "pkg.h"
#include "console.h"

static int pass = 0, fail = 0;

static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-56s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-56s %s\n", what, detail ? detail : ""); fail++; }
}

/*
 * A rotating pool, not one static buffer. A single shared buffer makes two
 * paths in the same expression alias each other, which is the inet_ntoa
 * trap this project already fell into once -- in a test, no less.
 */
static char g_dir[256];
static const char *P(const char *leaf) {
    static char pool[8][512];
    static int  n = 0;
    char *b = pool[n++ & 7];
    snprintf(b, sizeof(pool[0]), "%s/%s", g_dir, leaf);
    return b;
}

static void write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    fwrite(data, 1, len, f);
    fclose(f);
}

/* Reads a whole file. Caller frees. */
static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    b[n] = 0;
    fclose(f);
    *len = (size_t)n;
    return b;
}

/* ── bundles ────────────────────────────────────────────────── */

static void test_bundles(void) {
    char err[512] = "";
    char priv[UPD_B64_LEN], pub[UPD_B64_LEN];
    char buf[256];

    puts("\n--- keys ---");
    ok("Ed25519 keypair generated", upd_keygen(priv, pub) == 0, NULL);
    ok("public key is 44 base64 characters", strlen(pub) == 44, pub);

    char id1[UPD_KEYID_LEN], id2[UPD_KEYID_LEN];
    ok("key id derives from the base64 form",
       upd_keyid_from_b64(pub, id1) == 0 && strlen(id1) == 16, id1);
    ok("the same key always yields the same id",
       upd_keyid_from_b64(pub, id2) == 0 && strcmp(id1, id2) == 0, NULL);

    char priv2[UPD_B64_LEN], pub2[UPD_B64_LEN], id3[UPD_KEYID_LEN];
    upd_keygen(priv2, pub2);
    upd_keyid_from_b64(pub2, id3);
    ok("a different key yields a different id", strcmp(id1, id3) != 0, NULL);
    ok("a truncated key does not decode",
       upd_keyid_from_b64("AAAA", id2) != 0, NULL);

    puts("\n--- keyring ---");
    FILE *k = fopen(P("keys"), "w");
    fprintf(k, "# comment line\n\n%s release key\n", pub);
    fclose(k);

    upd_keyring_t ring;
    ok("keyring loads, comments and blanks skipped",
       upd_keyring_load(&ring, P("keys"), err, sizeof(err)) == 0 && ring.count == 1,
       err);
    ok("the loaded key carries its id",
       ring.count == 1 && strcmp(ring.key[0].id, id1) == 0, NULL);
    ok("comment preserved",
       ring.count == 1 && strcmp(ring.key[0].comment, "release key") == 0,
       ring.count ? ring.key[0].comment : "");
    ok("lookup by id finds it", upd_keyring_find(&ring, id1) != NULL, NULL);
    ok("lookup of an unknown id finds nothing",
       upd_keyring_find(&ring, "0000000000000000") == NULL, NULL);

    /* A keyring that silently dropped a bad line would reject every
     * update signed with the key on that line, with no explanation. */
    upd_keyring_t bad;
    write_file(P("badkeys"), "not-base64\n", 11);
    ok("a malformed keyring line is an error, not a skip",
       upd_keyring_load(&bad, P("badkeys"), err, sizeof(err)) != 0, err);
    write_file(P("emptykeys"), "# nothing here\n", 15);
    ok("an empty keyring is an error",
       upd_keyring_load(&bad, P("emptykeys"), err, sizeof(err)) != 0, err);

    puts("\n--- canonical signed material ---");
    upd_meta_t m;
    memset(&m, 0, sizeof(m));
    m.kind = UPD_KIND_IMAGE;
    snprintf(m.name, sizeof(m.name), "firex");
    snprintf(m.version, sizeof(m.version), "3.1.0");
    snprintf(m.build, sizeof(m.build), "2026-10-28T00:00:00Z");
    snprintf(m.arch, sizeof(m.arch), "x86_64");
    snprintf(m.requires, sizeof(m.requires), "3.0.0");
    snprintf(m.description, sizeof(m.description), "test release");
    snprintf(m.sha256, sizeof(m.sha256),
             "0000000000000000000000000000000000000000000000000000000000000000");
    m.size = 1234;

    /* Spelled out here independently of update.c, so a change to the
     * format has to be made in two places or this test fails. */
    const char *expect =
        "firex-update-v1\n"
        "kind=image\n"
        "name=firex\n"
        "version=3.1.0\n"
        "build=2026-10-28T00:00:00Z\n"
        "arch=x86_64\n"
        "size=1234\n"
        "sha256=0000000000000000000000000000000000000000000000000000000000000000\n"
        "requires=3.0.0\n"
        "description=test release\n";

    char mat[UPD_MAX_HEADER];
    int mlen = upd_signed_material(&m, mat, sizeof(mat));
    ok("the signed material is exactly the documented string",
       mlen > 0 && strcmp(mat, expect) == 0, NULL);
    ok("its length matches what was returned",
       mlen > 0 && (size_t)mlen == strlen(expect), NULL);

    /* Every field must actually reach the material, or editing it in a
     * header would not break the signature. */
    struct { const char *label; char *field; size_t len; } fields[] = {
        { "name",        m.name,        sizeof(m.name)        },
        { "version",     m.version,     sizeof(m.version)     },
        { "build",       m.build,       sizeof(m.build)       },
        { "arch",        m.arch,        sizeof(m.arch)        },
        { "requires",    m.requires,    sizeof(m.requires)    },
        { "description", m.description, sizeof(m.description) },
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        upd_meta_t t = m;
        char *dst = (char *)&t + ((char *)fields[i].field - (char *)&m);
        snprintf(dst, fields[i].len, "CHANGED");
        char other[UPD_MAX_HEADER];
        upd_signed_material(&t, other, sizeof(other));
        snprintf(buf, sizeof(buf), "(%s)", fields[i].label);
        ok("changing a field changes the signed material", strcmp(other, mat) != 0, buf);
    }
    {
        upd_meta_t t = m; t.size = 9999;
        char other[UPD_MAX_HEADER];
        upd_signed_material(&t, other, sizeof(other));
        ok("changing the size changes the signed material",
           strcmp(other, mat) != 0, "(size)");
        t = m; t.kind = UPD_KIND_PACKAGE;
        upd_signed_material(&t, other, sizeof(other));
        ok("changing the kind changes the signed material",
           strcmp(other, mat) != 0, "(kind)");
        t = m;
        snprintf(t.sha256, sizeof(t.sha256), "%064d", 1);
        upd_signed_material(&t, other, sizeof(other));
        ok("changing the payload digest changes the signed material",
           strcmp(other, mat) != 0, "(sha256)");
    }

    puts("\n--- create and verify ---");
    unsigned char payload[40000];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (unsigned char)(i * 31 + 7);
    write_file(P("payload.img"), payload, sizeof(payload));

    upd_meta_t sm;
    memset(&sm, 0, sizeof(sm));
    sm.kind = UPD_KIND_IMAGE;
    snprintf(sm.name, sizeof(sm.name), "firex");
    snprintf(sm.version, sizeof(sm.version), "3.1.0");
    snprintf(sm.build, sizeof(sm.build), "2026-10-28T00:00:00Z");
    snprintf(sm.requires, sizeof(sm.requires), "3.0.0");
    snprintf(sm.description, sizeof(sm.description), "phase 8 test bundle");

    ok("bundle created",
       upd_bundle_create(P("payload.img"), &sm, priv, P("good.fxu"),
                         err, sizeof(err)) == 0, err);
    ok("the payload size was filled in", sm.size == sizeof(payload), NULL);
    ok("the signer id is this key", strcmp(sm.signer, id1) == 0, sm.signer);
    ok("arch defaulted to x86_64", strcmp(sm.arch, "x86_64") == 0, sm.arch);

    upd_meta_t got;
    ok("header parses without any cryptography",
       upd_bundle_header(P("good.fxu"), &got, err, sizeof(err)) == 0, err);
    ok("the parsed version round-trips", strcmp(got.version, "3.1.0") == 0, got.version);
    ok("the parsed size round-trips", got.size == sizeof(payload), NULL);
    ok("the parsed digest round-trips", strcmp(got.sha256, sm.sha256) == 0, NULL);

    ok("a well-formed bundle verifies",
       upd_bundle_verify(P("good.fxu"), &ring, NULL, &got, err, sizeof(err)) == 0,
       err);

    /*
     * Signing independently of upd_bundle_create: if the verifier only
     * agreed with our own signer, a bug in the material could sit in both
     * halves and never show.
     */
    {
        unsigned char rawpriv[UPD_KEY_LEN];
        EVP_DecodeBlock(rawpriv, (const unsigned char *)priv, 44);
        EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                    rawpriv, UPD_KEY_LEN);
        char material[UPD_MAX_HEADER];
        int n = upd_signed_material(&got, material, sizeof(material));
        unsigned char sig[UPD_SIG_LEN];
        size_t sl = sizeof(sig);
        EVP_MD_CTX *mc = EVP_MD_CTX_new();
        EVP_DigestSignInit(mc, NULL, NULL, NULL, pk);
        int rc = EVP_DigestSign(mc, sig, &sl, (const unsigned char *)material,
                                (size_t)n);
        EVP_MD_CTX_free(mc);

        char sigb64[UPD_B64_LEN];
        EVP_EncodeBlock((unsigned char *)sigb64, sig, (int)sl);
        ok("signing the material separately reproduces the bundle signature",
           rc == 1 && strcmp(sigb64, got.signature) == 0, NULL);
        EVP_PKEY_free(pk);
    }

    puts("\n--- tampering ---");
    size_t blen = 0;
    unsigned char *bundle = read_file(P("good.fxu"), &blen);
    ok("bundle read back for tampering", bundle != NULL, NULL);

    /* The payload starts at got.payload_offset; flip a byte inside it. */
    unsigned char *t1 = malloc(blen);
    memcpy(t1, bundle, blen);
    t1[got.payload_offset + 100] ^= 0xff;
    write_file(P("t_payload.fxu"), t1, blen);
    free(t1);
    ok("a flipped payload byte is rejected",
       upd_bundle_verify(P("t_payload.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0,
       err);

    /* Edit the version in the header, same width so nothing shifts. */
    unsigned char *t2 = malloc(blen);
    memcpy(t2, bundle, blen);
    char *vp = strstr((char *)t2, "version: 3.1.0");
    if (vp) memcpy(vp + 9, "9.9.9", 5);
    write_file(P("t_version.fxu"), t2, blen);
    free(t2);
    ok("an edited version in the header is rejected",
       upd_bundle_verify(P("t_version.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0,
       err);

    /* The description is what an operator reads before approving. */
    unsigned char *t3 = malloc(blen);
    memcpy(t3, bundle, blen);
    char *dp = strstr((char *)t3, "description: phase 8 test bundle");
    if (dp) memcpy(dp + 13, "URGENT security fix!!", 21);
    write_file(P("t_desc.fxu"), t3, blen);
    free(t3);
    ok("an edited description is rejected",
       upd_bundle_verify(P("t_desc.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0,
       err);

    /* Truncation and extension. */
    write_file(P("t_short.fxu"), bundle, blen - 200);
    ok("a truncated payload is rejected",
       upd_bundle_verify(P("t_short.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0,
       err);

    unsigned char *t4 = malloc(blen + 200);
    memcpy(t4, bundle, blen);
    memset(t4 + blen, 0, 200);
    write_file(P("t_long.fxu"), t4, blen + 200);
    free(t4);
    ok("trailing bytes after the payload are rejected",
       upd_bundle_verify(P("t_long.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0,
       err);

    /* A valid signature from a key nobody trusts. */
    upd_meta_t em;
    memset(&em, 0, sizeof(em));
    snprintf(em.version, sizeof(em.version), "3.1.0");
    snprintf(em.build, sizeof(em.build), "2026-10-28T00:00:00Z");
    upd_bundle_create(P("payload.img"), &em, priv2, P("evil.fxu"), err, sizeof(err));
    ok("a bundle signed by an untrusted key is rejected",
       upd_bundle_verify(P("evil.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0,
       err);

    /* An empty keyring must refuse everything rather than wave it through. */
    upd_keyring_t none;
    memset(&none, 0, sizeof(none));
    ok("with no trusted keys nothing verifies",
       upd_bundle_verify(P("good.fxu"), &none, NULL, NULL, err, sizeof(err)) != 0,
       err);

    /* Duplicate header keys. */
    {
        char *dup = malloc(blen + 64);
        char *at = strstr((char *)bundle, "version: 3.1.0");
        size_t pre = (size_t)(at - (char *)bundle);
        memcpy(dup, bundle, pre);
        memcpy(dup + pre, "version: 9.9.9\n", 15);
        memcpy(dup + pre + 15, bundle + pre, blen - pre);
        write_file(P("t_dup.fxu"), dup, blen + 15);
        free(dup);
        ok("a header that sets a key twice is rejected",
           upd_bundle_verify(P("t_dup.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0,
           err);
    }

    /* Not a bundle at all. */
    write_file(P("junk.fxu"), "hello world\n", 12);
    ok("a file with the wrong magic is rejected",
       upd_bundle_verify(P("junk.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0, err);
    write_file(P("noseP.fxu"), "FIREXUP1\nversion: 1\n", 20);
    ok("a header with no separator is rejected",
       upd_bundle_verify(P("noseP.fxu"), &ring, NULL, NULL, err, sizeof(err)) != 0, err);

    ok("the untouched bundle still verifies after all of that",
       upd_bundle_verify(P("good.fxu"), &ring, NULL, NULL, err, sizeof(err)) == 0,
       err);

    puts("\n--- minimum version ---");
    ok("requires 3.0.0 blocks a 2.9.0 system",
       upd_bundle_verify(P("good.fxu"), &ring, "2.9.0", NULL, err, sizeof(err)) != 0,
       err);
    ok("requires 3.0.0 allows a 3.0.0 system",
       upd_bundle_verify(P("good.fxu"), &ring, "3.0.0", NULL, err, sizeof(err)) == 0,
       err);
    ok("requires 3.0.0 allows a 3.10.0 system",
       upd_bundle_verify(P("good.fxu"), &ring, "3.10.0", NULL, err, sizeof(err)) == 0,
       err);

    ok("3.10.0 is newer than 3.9.0",  upd_version_cmp("3.10.0", "3.9.0") > 0, NULL);
    ok("3.9.0 is older than 3.10.0",  upd_version_cmp("3.9.0", "3.10.0") < 0, NULL);
    ok("3.1 equals 3.1.0",            upd_version_cmp("3.1", "3.1.0") == 0, NULL);
    ok("3.0.1 is newer than 3.0.0",   upd_version_cmp("3.0.1", "3.0.0") > 0, NULL);
    ok("equal versions compare equal", upd_version_cmp("3.0.0", "3.0.0") == 0, NULL);

    puts("\n--- extraction ---");
    ok("payload extracts from a verified bundle",
       upd_bundle_extract(P("good.fxu"), &ring, P("out.img"), err, sizeof(err)) == 0,
       err);
    size_t olen = 0;
    unsigned char *outp = read_file(P("out.img"), &olen);
    ok("the extracted payload is byte-identical",
       outp && olen == sizeof(payload) && memcmp(outp, payload, olen) == 0, NULL);
    free(outp);

    ok("extraction from a tampered bundle refuses",
       upd_bundle_extract(P("t_payload.fxu"), &ring, P("no.img"),
                          err, sizeof(err)) != 0, err);
    ok("and leaves no output file behind", access(P("no.img"), F_OK) != 0, NULL);

    free(bundle);
}

/* ── A/B slots ──────────────────────────────────────────────── */

static void test_slots(void) {
    slots_t s;
    char err[256] = "";
    char buf[128];

    puts("\n--- slot defaults ---");
    slots_init(&s);
    ok("a fresh appliance runs slot a", s.running == SLOT_A, NULL);
    ok("slot a starts good", s.slot[SLOT_A].state == SLOT_GOOD, NULL);
    ok("slot b starts unused", s.slot[SLOT_B].state == SLOT_UNUSED, NULL);
    ok("the next boot is the running slot", s.next == SLOT_A, NULL);
    ok("labels are set", strcmp(s.slot[SLOT_B].label, "firex-root-b") == 0,
       s.slot[SLOT_B].label);
    ok("the update target is the slot that is not running",
       slots_target(&s) == SLOT_B, NULL);

    puts("\n--- installing into the spare slot ---");
    ok("an update may not be written to the running slot",
       slots_begin_update(&s, SLOT_A, "3.1.0", 3) != 0, NULL);
    ok("the running slot is untouched by that refusal",
       s.slot[SLOT_A].state == SLOT_GOOD &&
       strcmp(s.slot[SLOT_A].version, "3.0.0") == 0, NULL);

    ok("an update installs into the spare slot",
       slots_begin_update(&s, SLOT_B, "3.1.0", 3) == 0, NULL);
    ok("the spare is now pending", s.slot[SLOT_B].state == SLOT_PENDING, NULL);
    ok("with a full try budget", s.slot[SLOT_B].tries_left == 3, NULL);
    ok("and is selected for the next boot", s.next == SLOT_B, NULL);
    ok("the running slot is still good", s.slot[SLOT_A].state == SLOT_GOOD, NULL);
    ok("an install stamps the time", s.slot[SLOT_B].installed > 0, NULL);
    ok("tries default when none is given",
       slots_begin_update(&s, SLOT_B, "3.1.0", 0) == 0 &&
       s.slot[SLOT_B].tries_left == SLOT_DEFAULT_TRIES, NULL);

    puts("\n--- the new slot boots and confirms ---");
    slots_t good = s;
    good.running = SLOT_B;                 /* we rebooted into it */
    ok("the first boot spends one attempt and stays",
       slots_boot_attempt(&good) == false, NULL);
    snprintf(buf, sizeof(buf), "(%d left)", good.slot[SLOT_B].tries_left);
    ok("attempts counted down", good.slot[SLOT_B].tries_left == 2, buf);
    ok("still pending until it confirms",
       good.slot[SLOT_B].state == SLOT_PENDING, NULL);

    slots_confirm(&good);
    ok("confirming marks the running slot good",
       good.slot[SLOT_B].state == SLOT_GOOD, NULL);
    ok("confirming clears the try counter", good.slot[SLOT_B].tries_left == 0, NULL);
    ok("and pins the next boot here", good.next == SLOT_B, NULL);
    ok("a confirmed slot spends no further attempts",
       slots_boot_attempt(&good) == false && good.slot[SLOT_B].tries_left == 0, NULL);
    ok("the old slot is still good and available",
       good.slot[SLOT_A].state == SLOT_GOOD, NULL);

    puts("\n--- the new slot never comes up ---");
    slots_t bad = s;
    bad.running = SLOT_B;
    bad.slot[SLOT_B].tries_left = 3;
    bad.slot[SLOT_B].state = SLOT_PENDING;

    ok("attempt 1 of 3 stays put", slots_boot_attempt(&bad) == false, NULL);
    ok("attempt 2 of 3 stays put", slots_boot_attempt(&bad) == false, NULL);
    bool fell_back = slots_boot_attempt(&bad);
    ok("attempt 3 of 3 gives up", fell_back == true, NULL);
    ok("the failed slot is marked bad", bad.slot[SLOT_B].state == SLOT_BAD, NULL);
    ok("the next boot returns to the working slot", bad.next == SLOT_A, NULL);
    ok("the working slot was never touched",
       bad.slot[SLOT_A].state == SLOT_GOOD, NULL);

    puts("\n--- when neither slot is usable ---");
    slots_t grim;
    slots_init(&grim);
    grim.slot[SLOT_A].state = SLOT_BAD;
    grim.slot[SLOT_B].state = SLOT_PENDING;
    grim.slot[SLOT_B].tries_left = 1;
    grim.running = SLOT_B;
    ok("a last attempt with no good fallback does not ask for a reboot",
       slots_boot_attempt(&grim) == false, NULL);
    ok("it still records that this slot failed",
       grim.slot[SLOT_B].state == SLOT_BAD, NULL);
    ok("and keeps running where it is rather than rebooting into a bad slot",
       grim.next == SLOT_B, NULL);

    puts("\n--- operator rollback ---");
    slots_t r = good;                /* running b (good), a good */
    ok("rollback to a good slot is allowed",
       slots_rollback(&r, err, sizeof(err)) == 0, err);
    ok("and selects it for the next boot", r.next == SLOT_A, NULL);
    ok("a confirmed slot is not demoted by rolling away from it",
       r.slot[SLOT_B].state == SLOT_GOOD, NULL);

    slots_t r2;
    slots_init(&r2);                 /* b is unused */
    ok("rollback into an unused slot is refused",
       slots_rollback(&r2, err, sizeof(err)) != 0, err);
    ok("and says why", strstr(err, "unused") != NULL, err);

    slots_t r3;
    slots_init(&r3);
    slots_begin_update(&r3, SLOT_B, "3.1.0", 3);
    r3.running = SLOT_B;
    ok("rolling away from an unconfirmed slot marks it bad",
       slots_rollback(&r3, err, sizeof(err)) == 0 &&
       r3.slot[SLOT_B].state == SLOT_BAD, err);

    puts("\n--- state file ---");
    slots_t w;
    slots_init(&w);
    slots_begin_update(&w, SLOT_B, "3.1.0", 2);
    w.slot[SLOT_B].installed = 1761000000ULL;
    ok("state saves", slots_save(&w, P("slots.conf"), err, sizeof(err)) == 0, err);

    slots_t rd;
    ok("state loads", slots_load(&rd, P("slots.conf"), err, sizeof(err)) == 0, err);
    ok("running slot round-trips", rd.running == w.running, NULL);
    ok("next slot round-trips", rd.next == SLOT_B, NULL);
    ok("state round-trips", rd.slot[SLOT_B].state == SLOT_PENDING, NULL);
    ok("version round-trips", strcmp(rd.slot[SLOT_B].version, "3.1.0") == 0,
       rd.slot[SLOT_B].version);
    ok("tries round-trip", rd.slot[SLOT_B].tries_left == 2, NULL);
    ok("label round-trips", strcmp(rd.slot[SLOT_A].label, "firex-root-a") == 0, NULL);
    ok("install time round-trips", rd.slot[SLOT_B].installed == 1761000000ULL, NULL);

    slots_t miss;
    int rc = slots_load(&miss, P("does-not-exist.conf"), err, sizeof(err));
    ok("a missing state file is reported but not fatal", rc == 1, err);
    ok("and leaves usable defaults",
       miss.slot[SLOT_A].state == SLOT_GOOD && miss.running == SLOT_A, NULL);

    ok("the temporary file is not left behind",
       access(P("slots.conf.tmp"), F_OK) != 0, NULL);

    puts("\n--- grub.cfg generation ---");
    char g[4096];
    slots_t gs;
    slots_init(&gs);
    slots_begin_update(&gs, SLOT_B, "3.1.0", 3);
    int gl = slots_grub_config(&gs, g, sizeof(g));
    ok("grub.cfg generated", gl > 0, NULL);
    ok("it selects the first entry", strstr(g, "set default=0") != NULL, NULL);
    ok("serial console is configured", strstr(g, "serial --unit=0") != NULL, NULL);

    char *first_b = strstr(g, "slot b");
    char *first_a = strstr(g, "slot a");
    ok("the pending slot is listed first, so default=0 picks it",
       first_b && first_a && first_b < first_a, NULL);
    ok("both roots appear", strstr(g, "root=LABEL=firex-root-a") &&
       strstr(g, "root=LABEL=firex-root-b"), NULL);
    ok("the kernel is told which slot it is",
       strstr(g, "firex.slot=a") && strstr(g, "firex.slot=b"), NULL);
    ok("the entry shows the slot state", strstr(g, "pending") != NULL, NULL);

    /* After a fallback the order has to flip, or the bootloader would
     * keep selecting the slot that just failed. */
    slots_t fs = gs;
    fs.running = SLOT_B;
    fs.slot[SLOT_B].tries_left = 1;
    slots_boot_attempt(&fs);
    slots_grub_config(&fs, g, sizeof(g));
    char *a2 = strstr(g, "slot a"), *b2 = strstr(g, "slot b");
    ok("after a fallback the good slot is listed first", a2 && b2 && a2 < b2, NULL);

    ok("a buffer that is too small is refused rather than truncated",
       slots_grub_config(&gs, g, 300) < 0, NULL);

    puts("\n--- boot splash ---");
    /*
     * The splash is three things that have to agree: a theme GRUB can
     * find, "splash" on the kernel line, and tty0 named last so Plymouth
     * renders on the screen rather than down the serial port. Any one of
     * them alone is a black screen with nothing to say why.
     */
    slots_grub_config(&gs, g, sizeof(g));
    ok("the kernel line asks for the splash",
       strstr(g, " quiet splash") != NULL, NULL);
    /* Naming tty0 last is necessary but not sufficient: Plymouth scans
     * for serial consoles independently and, finding ttyS0, prints the
     * boot log instead of drawing anything. The appliance booted to a
     * screen of systemd lines because of exactly this. */
    ok("Plymouth is told to ignore the serial console",
       strstr(g, "plymouth.ignore-serial-consoles") != NULL, NULL);
    /* The shipped firex.conf is written in eth0/eth1. Predictable naming
     * renames them and every [port:ethN] stanza silently stops matching,
     * which looks like an appliance that boots fine and segments nothing. */
    ok("classic interface names are requested",
       strstr(g, "net.ifnames=0") && strstr(g, "biosdevname=0"), NULL);
    ok("a graphical terminal is selected",
       strstr(g, "terminal_output gfxterm serial") != NULL, NULL);
    ok("the theme is referenced",
       strstr(g, "set theme=$prefix/themes/firex/theme.txt") != NULL, NULL);
    ok("the font is loaded before the theme is used",
       strstr(g, "loadfont $prefix/fonts/unicode.pf2") &&
       strstr(g, "loadfont") < strstr(g, "set theme="), NULL);
    ok("png support is loaded for the background",
       strstr(g, "insmod png") != NULL, NULL);
    ok("the payload is kept, so the kernel inherits a framebuffer",
       strstr(g, "set gfxpayload=keep") != NULL, NULL);

    /* Plymouth follows /dev/console, which the kernel points at the LAST
     * console= on the line. tty0 has to win, or the splash is text on the
     * serial port and the monitor stays blank. */
    char *ttyS = strstr(g, "console=ttyS0");
    char *tty0 = strstr(g, "console=tty0");
    ok("tty0 is named after ttyS0 on the kernel line",
       ttyS && tty0 && ttyS < tty0, NULL);

    /* The plain text menu is selected before the graphical one is tried,
     * so a missing font or video driver costs the artwork and not the
     * boot. */
    char *plain = strstr(g, "terminal_output console serial");
    char *gfx   = strstr(g, "terminal_output gfxterm serial");
    ok("the text terminal is the fallback, chosen first",
       plain && gfx && plain < gfx, NULL);
    ok("the graphical block is guarded by the font load",
       strstr(g, "if loadfont") != NULL, NULL);

    slots_set_splash(false);
    slots_grub_config(&gs, g, sizeof(g));
    ok("--no-splash drops the kernel argument",
       strstr(g, "splash") == NULL, NULL);
    ok("and takes the Plymouth serial flag with it",
       strstr(g, "ignore-serial-consoles") == NULL, NULL);
    ok("but interface naming is not a splash setting, so it stays",
       strstr(g, "net.ifnames=0") != NULL, NULL);
    ok("but still boots both slots",
       strstr(g, "root=LABEL=firex-root-a") &&
       strstr(g, "root=LABEL=firex-root-b"), NULL);
    ok("and still names tty0 last",
       strstr(g, "console=ttyS0,115200n8 console=tty0") != NULL, NULL);

    slots_set_splash(true);
    slots_grub_config(&gs, g, sizeof(g));
    ok("the setting is restored for the rest of the run",
       strstr(g, " quiet splash") != NULL, NULL);

    puts("\n--- slot naming ---");
    ok("slot names", !strcmp(slot_name(SLOT_A), "a") &&
       !strcmp(slot_name(SLOT_B), "b"), NULL);
    ok("state names", !strcmp(slot_state_name(SLOT_PENDING), "pending") &&
       !strcmp(slot_state_name(SLOT_GOOD), "good") &&
       !strcmp(slot_state_name(SLOT_BAD), "bad") &&
       !strcmp(slot_state_name(SLOT_UNUSED), "unused"), NULL);
}

/* ── packages ───────────────────────────────────────────────── */

static void test_packages(void) {
    char why[256] = "";
    char buf[128];

    puts("\n--- package path safety ---");
    const char *safe[] = {
        "bin/tool", "lib/libfoo.so.1", "share/doc/README",
        "etc/foo.conf", "a", "a/b/c/d/e", "x.y-z_1+2",
        "share/locale/en_GB/LC_MESSAGES/foo.mo", "dir/",
    };
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); i++) {
        snprintf(buf, sizeof(buf), "'%s'", safe[i]);
        ok("accepted", pkg_path_safe(safe[i], why, sizeof(why)), buf);
    }

    const char *unsafe[] = {
        "/etc/shadow",            /* absolute                        */
        "../etc/shadow",          /* climbs immediately              */
        "bin/../../etc/shadow",   /* climbs in the middle            */
        "a/b/..",                 /* climbs at the end               */
        "..",                     /* bare                            */
        "bin/foo;rm -rf /",       /* shell metacharacters            */
        "bin/$(id)",              /* command substitution            */
        "bin/`id`",               /* the other kind                  */
        "bin/foo bar",            /* space: splits a command         */
        "bin/foo\tbar",           /* tab                             */
        "bin/foo'bar",            /* quote                           */
        "bin/foo\"bar",           /* the other quote                 */
        "bin/foo|cat",            /* pipe                            */
        "bin/foo&",               /* background                      */
        "bin/foo\nbar",           /* newline: a second command       */
        "~/.ssh/authorized_keys", /* tilde expansion                 */
        "bin\\foo",               /* backslash                       */
        "bin/foo*",               /* glob                            */
        "",                       /* empty                           */
    };
    for (size_t i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
        snprintf(buf, sizeof(buf), "'%.40s'", unsafe[i]);
        ok("refused", !pkg_path_safe(unsafe[i], why, sizeof(why)), buf);
    }

    /* "..foo" and "foo..bar" are ordinary names, not traversal. Rejecting
     * them would be a bug in the other direction. */
    ok("'..foo' is an ordinary name", pkg_path_safe("..foo", why, sizeof(why)), NULL);
    ok("'foo..bar' is an ordinary name",
       pkg_path_safe("foo..bar", why, sizeof(why)), NULL);
    ok("'a/..b/c' is an ordinary name",
       pkg_path_safe("a/..b/c", why, sizeof(why)), NULL);

    char longp[PKG_PATH_LEN + 16];
    memset(longp, 'a', sizeof(longp) - 1);
    longp[sizeof(longp) - 1] = '\0';
    ok("an over-long member name is refused",
       !pkg_path_safe(longp, why, sizeof(why)), why);

    ok("a refusal explains itself",
       !pkg_path_safe("../etc/shadow", why, sizeof(why)) && strlen(why) > 10, why);

    puts("\n--- checking a whole listing ---");
    char *good_list[] = { (char *)"bin/a", (char *)"bin/b", (char *)"lib/c" };
    ok("a clean listing passes", pkg_listing_check(good_list, 3, why, sizeof(why)) < 0,
       NULL);

    char *mixed[] = { (char *)"bin/a", (char *)"../../etc/shadow", (char *)"bin/c" };
    int bad = pkg_listing_check(mixed, 3, why, sizeof(why));
    ok("one bad member fails the listing", bad == 1, NULL);
    ok("and it reports which one", strstr(why, "shadow") != NULL, why);

    puts("\n--- install records ---");
    pkg_ctx_t pc;
    mkdir(P("pkgdb"), 0755);
    pkg_init(&pc, P("pkgroot"), P("pkgdb"));
    ok("the root is set", strstr(pc.root, "pkgroot") != NULL, pc.root);

    pkg_info_t info;
    memset(&info, 0, sizeof(info));
    snprintf(info.name, sizeof(info.name), "snort-rules");
    snprintf(info.version, sizeof(info.version), "2.4.1");
    snprintf(info.description, sizeof(info.description), "extra signatures");
    snprintf(info.sha256, sizeof(info.sha256), "%064d", 7);
    info.installed = 1761000000ULL;

    char *files[] = { (char *)"share/", (char *)"share/rules.ids",
                      (char *)"bin/update-rules" };
    char err[256] = "";
    ok("record written",
       pkg_record_write(&pc, &info, files, 3, err, sizeof(err)) == 0, err);

    pkg_info_t back;
    ok("record read back",
       pkg_record_read(&pc, "snort-rules", &back, err, sizeof(err)) == 0, err);
    ok("name round-trips", strcmp(back.name, "snort-rules") == 0, back.name);
    ok("version round-trips", strcmp(back.version, "2.4.1") == 0, back.version);
    ok("description round-trips",
       strcmp(back.description, "extra signatures") == 0, back.description);
    ok("digest round-trips", strcmp(back.sha256, info.sha256) == 0, NULL);
    ok("install time round-trips", back.installed == 1761000000ULL, NULL);
    ok("file count round-trips", back.file_count == 3, NULL);

    ok("reading a package that is not installed fails",
       pkg_record_read(&pc, "nope", &back, err, sizeof(err)) != 0, err);

    ok("the database lists it", pkg_db_load(&pc, err, sizeof(err)) == 0 &&
       pc.count == 1, NULL);
    ok("and it can be found by name", pkg_find(&pc, "snort-rules") != NULL, NULL);
    ok("an unknown name is not found", pkg_find(&pc, "other") == NULL, NULL);

    puts("\n--- install and remove plans ---");
    upd_meta_t pm;
    memset(&pm, 0, sizeof(pm));
    pm.kind = UPD_KIND_PACKAGE;
    snprintf(pm.name, sizeof(pm.name), "snort-rules");
    snprintf(pm.version, sizeof(pm.version), "2.4.1");

    pkg_plan_t plan;
    ok("an install plan is produced",
       pkg_plan_install(&pc, &pm, P("staged.tar.gz"), &plan) > 0, NULL);

    bool has_tar = false, no_same_owner = false, no_same_perm = false,
         into_root = false;
    for (int i = 0; i < plan.count; i++) {
        if (strstr(plan.cmd[i], "tar -xzf"))              has_tar = true;
        if (strstr(plan.cmd[i], "--no-same-owner"))       no_same_owner = true;
        if (strstr(plan.cmd[i], "--no-same-permissions")) no_same_perm = true;
        if (strstr(plan.cmd[i], "pkgroot"))               into_root = true;
    }
    ok("it extracts the archive", has_tar, NULL);
    ok("it refuses to restore ownership from the archive", no_same_owner, NULL);
    ok("it refuses to restore modes, so no setuid binary survives",
       no_same_perm, NULL);
    ok("it extracts into the package root", into_root, NULL);

    /* Every command in the plan has to be one this system's tools accept.
     * A flag that does not exist turns into a half-done install. */
    bool plan_runs = true;
    for (int i = 0; i < plan.count; i++) {
        if (plan.cmd[i][0] == '#') continue;
        char probe[PKG_CMD_LEN + 64];
        const char *sp = strchr(plan.cmd[i], ' ');
        if (!sp) continue;
        snprintf(probe, sizeof(probe), "command -v %.*s >/dev/null 2>&1",
                 (int)(sp - plan.cmd[i]), plan.cmd[i]);
        if (system(probe) != 0) plan_runs = false;
    }
    ok("every program the plan calls exists on this system", plan_runs, NULL);

    pkg_plan_t rp;
    ok("a remove plan is produced", pkg_plan_remove(&pc, &back, &rp) > 0, NULL);
    bool clears_db = false;
    for (int i = 0; i < rp.count; i++)
        if (strstr(rp.cmd[i], "snort-rules.pkg")) clears_db = true;
    ok("it clears the install record", clears_db, NULL);

    puts("\n--- installing a real archive ---");
    /* Build a small tarball and run it through the whole path: sign,
     * verify, list, check every member, extract, record. */
    char priv[UPD_B64_LEN], pub[UPD_B64_LEN];
    upd_keygen(priv, pub);
    FILE *kf = fopen(P("pkgkeys"), "w");
    fprintf(kf, "%s test\n", pub);
    fclose(kf);
    upd_keyring_t ring;
    upd_keyring_load(&ring, P("pkgkeys"), err, sizeof(err));

    mkdir(P("src"), 0755);
    mkdir(P("src/bin"), 0755);
    write_file(P("src/bin/hello"), "#!/bin/sh\necho hi\n", 18);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "tar -czf %s -C %s bin 2>/dev/null",
             P("hello.tar.gz"), P("src"));
    int tar_rc = system(cmd);
    ok("a test archive was built", tar_rc == 0, NULL);

    upd_meta_t hm;
    memset(&hm, 0, sizeof(hm));
    hm.kind = UPD_KIND_PACKAGE;
    snprintf(hm.name, sizeof(hm.name), "hello");
    snprintf(hm.version, sizeof(hm.version), "1.0.0");
    snprintf(hm.build, sizeof(hm.build), "2026-10-28T00:00:00Z");
    ok("the package bundle is signed",
       upd_bundle_create(P("hello.tar.gz"), &hm, priv, P("hello.fxp"),
                         err, sizeof(err)) == 0, err);

    pkg_plan_t ip;
    ok("a dry run accepts it",
       pkg_install(&pc, P("hello.fxp"), &ring, true, &ip, err, sizeof(err)) == 0, err);
    ok("a dry run installs nothing",
       access(P("pkgroot/bin/hello"), F_OK) != 0, NULL);

    ok("the real install succeeds",
       pkg_install(&pc, P("hello.fxp"), &ring, false, NULL, err, sizeof(err)) == 0,
       err);
    ok("the file landed under the package root",
       access(P("pkgroot/bin/hello"), F_OK) == 0, NULL);
    ok("it is recorded", pkg_find(&pc, "hello") != NULL, NULL);
    ok("the staging copy was cleaned up",
       access(P("pkgdb/.staging-hello.tar.gz"), F_OK) != 0, NULL);

    ok("removal succeeds",
       pkg_remove(&pc, "hello", false, NULL, err, sizeof(err)) == 0, err);
    ok("the file is gone", access(P("pkgroot/bin/hello"), F_OK) != 0, NULL);
    ok("the record is gone", pkg_find(&pc, "hello") == NULL, NULL);

    puts("\n--- hostile archives ---");
    /* A system image offered where a package is expected. */
    upd_meta_t im;
    memset(&im, 0, sizeof(im));
    im.kind = UPD_KIND_IMAGE;
    snprintf(im.version, sizeof(im.version), "3.1.0");
    upd_bundle_create(P("hello.tar.gz"), &im, priv, P("asimage.fxu"), err, sizeof(err));
    ok("a system image is not installable as a package",
       pkg_install(&pc, P("asimage.fxu"), &ring, true, NULL, err, sizeof(err)) != 0,
       err);

    /* An archive that climbs out of the root. */
    mkdir(P("eviltree"), 0755);
    snprintf(cmd, sizeof(cmd),
             "mkdir -p %s/sub && echo pwned > %s/sub/x && "
             "tar -czf %s -C %s --transform 's|sub/x|../../../etc/pwned|' sub/x "
             "2>/dev/null",
             P("eviltree"), P("eviltree"), P("escape.tar.gz"), P("eviltree"));
    if (system(cmd) == 0) {
        upd_meta_t xm;
        memset(&xm, 0, sizeof(xm));
        xm.kind = UPD_KIND_PACKAGE;
        snprintf(xm.name, sizeof(xm.name), "escape");
        snprintf(xm.version, sizeof(xm.version), "1.0.0");
        upd_bundle_create(P("escape.tar.gz"), &xm, priv, P("escape.fxp"),
                          err, sizeof(err));
        ok("a validly signed package that climbs out of the root is refused",
           pkg_install(&pc, P("escape.fxp"), &ring, true, NULL, err, sizeof(err)) != 0,
           err);
        ok("and the refusal names the reason",
           strstr(err, "..") != NULL || strstr(err, "refusing") != NULL, err);
    } else {
        ok("tar could not build the traversal archive (skipped)", 1, NULL);
        ok("traversal refusal not exercised (skipped)", 1, NULL);
    }

    /* An archive containing a symlink. */
    snprintf(cmd, sizeof(cmd),
             "mkdir -p %s/l && ln -sf /etc/shadow %s/l/link && "
             "tar -czf %s -C %s l 2>/dev/null",
             P("linktree"), P("linktree"), P("link.tar.gz"), P("linktree"));
    if (system(cmd) == 0) {
        upd_meta_t lm;
        memset(&lm, 0, sizeof(lm));
        lm.kind = UPD_KIND_PACKAGE;
        snprintf(lm.name, sizeof(lm.name), "linky");
        snprintf(lm.version, sizeof(lm.version), "1.0.0");
        upd_bundle_create(P("link.tar.gz"), &lm, priv, P("link.fxp"),
                          err, sizeof(err));
        ok("a package containing a symlink is refused",
           pkg_install(&pc, P("link.fxp"), &ring, true, NULL, err, sizeof(err)) != 0,
           err);
        ok("and says it was a link", strstr(err, "link") != NULL, err);
    } else {
        ok("symlink archive could not be built (skipped)", 1, NULL);
        ok("link refusal not exercised (skipped)", 1, NULL);
    }

    /* An unsigned or wrongly signed package. */
    upd_keyring_t other;
    memset(&other, 0, sizeof(other));
    ok("a package with no trusted key is refused",
       pkg_install(&pc, P("hello.fxp"), &other, true, NULL, err, sizeof(err)) != 0,
       err);
}

/* ── console ────────────────────────────────────────────────── */

static void test_console(void) {
    char buf[160];

    puts("\n--- console input parsing ---");
    /*
     * The whole mapping, not a sample of it. Operators learn these
     * numbers by muscle memory, so inserting an option in the middle
     * silently moves "reboot" under somebody's finger. Pinning every
     * number means a renumbering has to be done on purpose, here, rather
     * than discovered on an appliance.
     */
    static const struct { const char *in; console_action_t want; } MAP[] = {
        { "0",  CON_LOGOUT   }, { "1",  CON_STATUS   }, { "2",  CON_IFACES  },
        { "3",  CON_SETIP    }, { "4",  CON_PASSWD   }, { "5",  CON_PING    },
        { "6",  CON_RELOAD   }, { "7",  CON_UPDATE   }, { "8",  CON_SLOTS   },
        { "9",  CON_ROLLBACK }, { "10", CON_PACKAGES }, { "11", CON_FACTORY },
        { "12", CON_SHELL    }, { "13", CON_DESKTOP  }, { "14", CON_REBOOT  },
        { "15", CON_HALT     },
    };
    bool map_ok = true;
    for (size_t i = 0; i < sizeof(MAP) / sizeof(MAP[0]); i++)
        if (console_lookup(MAP[i].in) != MAP[i].want) {
            printf("        option %s went to %d, expected %d\n",
                   MAP[i].in, console_lookup(MAP[i].in), MAP[i].want);
            map_ok = false;
        }
    ok("every menu number selects the option printed beside it", map_ok,
       "0-15");

    /* The two that end a session must not be reachable by a slip. */
    ok("reboot and halt are the last two, not in the middle",
       console_lookup("14") == CON_REBOOT && console_lookup("15") == CON_HALT,
       NULL);
    ok("the number past the end is refused",
       console_lookup("16") == CON_INVALID, NULL);
    ok("' 5 ' tolerates spaces",   console_lookup(" 5 ") == CON_PING, NULL);
    ok("'5\\n' tolerates a newline", console_lookup("5\n") == CON_PING, NULL);
    ok("an empty line redraws",    console_lookup("") == CON_NONE, NULL);
    ok("a bare newline redraws",   console_lookup("\n") == CON_NONE, NULL);
    ok("whitespace only redraws",  console_lookup("   ") == CON_NONE, NULL);

    /*
     * The dangerous case: a line that starts with a digit but is not one
     * of the options. Reading "13x" as 13 would reboot the appliance
     * because someone fumbled a paste.
     */
    ok("'14x' is not reboot",      console_lookup("14x") == CON_INVALID, NULL);
    ok("'1 4' is not reboot",      console_lookup("1 4") == CON_INVALID, NULL);
    ok("'13 14' is refused",       console_lookup("13 14") == CON_INVALID, NULL);
    ok("'abc' is refused",         console_lookup("abc") == CON_INVALID, NULL);
    ok("'99' is refused",          console_lookup("99") == CON_INVALID, NULL);
    ok("'-1' is refused",          console_lookup("-1") == CON_INVALID, NULL);
    ok("'0x0' is refused",         console_lookup("0x0") == CON_INVALID, NULL);
    ok("a NULL line is refused",   console_lookup(NULL) == CON_INVALID, NULL);

    puts("\n--- the menu table ---");
    int n = 0;
    const console_item_t *items = console_items(&n);
    snprintf(buf, sizeof(buf), "(%d)", n);
    ok("the menu has entries", items && n >= 10, buf);

    bool dup = false;
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (items[i].choice == items[j].choice ||
                items[i].action == items[j].action) dup = true;
    ok("no option number or action appears twice", !dup, NULL);

    bool all_labelled = true, all_lookupable = true;
    for (int i = 0; i < n; i++) {
        if (!items[i].label || !items[i].label[0]) all_labelled = false;
        char s[16];
        snprintf(s, sizeof(s), "%d", items[i].choice);
        if (console_lookup(s) != items[i].action) all_lookupable = false;
    }
    ok("every entry has a label", all_labelled, NULL);
    ok("every entry's number maps back to its action", all_lookupable, NULL);

    /* The things that cannot be undone must announce themselves. */
    const console_action_t risky[] = { CON_REBOOT, CON_HALT, CON_FACTORY,
                                       CON_UPDATE, CON_ROLLBACK };
    bool all_risky_marked = true;
    for (size_t i = 0; i < sizeof(risky) / sizeof(risky[0]); i++) {
        const console_item_t *it = console_item_for(risky[i]);
        if (!it || !it->destructive) all_risky_marked = false;
    }
    ok("reboot, halt, factory reset, update and rollback all confirm first",
       all_risky_marked, NULL);

    const console_action_t harmless[] = { CON_STATUS, CON_IFACES, CON_SLOTS,
                                          CON_PING, CON_LOGOUT };
    bool none_marked = true;
    for (size_t i = 0; i < sizeof(harmless) / sizeof(harmless[0]); i++) {
        const console_item_t *it = console_item_for(harmless[i]);
        if (!it || it->destructive) none_marked = false;
    }
    ok("read-only options do not ask for confirmation", none_marked, NULL);

    bool root_right = true;
    const console_item_t *st = console_item_for(CON_STATUS);
    const console_item_t *rb = console_item_for(CON_REBOOT);
    if (!st || st->needs_root) root_right = false;
    if (!rb || !rb->needs_root) root_right = false;
    ok("showing status needs no root, rebooting does", root_right, NULL);

    puts("\n--- rendering ---");
    slots_t s;
    slots_init(&s);
    char out[4096];
    int len = console_render(out, sizeof(out), "fw-edge-01", "3.0.0", &s);
    ok("the menu renders", len > 0, NULL);
    ok("it names the host", strstr(out, "fw-edge-01") != NULL, NULL);
    ok("it names the product", strstr(out, "FireX") != NULL, NULL);
    ok("it shows the version", strstr(out, "3.0.0") != NULL, NULL);
    ok("it shows the running slot", strstr(out, "slot a") != NULL, NULL);
    ok("it prompts for input", strstr(out, "Enter an option") != NULL, NULL);
    ok("it explains the confirmation marker",
       strstr(out, "asks for confirmation") != NULL, NULL);

    bool every_label = true;
    for (int i = 0; i < n; i++)
        if (!strstr(out, items[i].label)) every_label = false;
    ok("every menu entry appears in the rendered text", every_label, NULL);

    ok("a buffer that is too small is refused rather than truncated",
       console_render(out, 100, "h", "1", &s) < 0, NULL);
    ok("it renders with no slot information at all",
       console_render(out, sizeof(out), NULL, NULL, NULL) > 0, NULL);

    puts("\n--- the slot summary line ---");
    slots_t q;
    slots_init(&q);
    ok("a settled system reads plainly",
       console_slot_line(&q, buf, sizeof(buf)) > 0 &&
       strstr(buf, "slot a") && strstr(buf, "good"), buf);

    slots_begin_update(&q, SLOT_B, "3.1.0", 3);
    ok("a staged update announces the next boot",
       console_slot_line(&q, buf, sizeof(buf)) > 0 && strstr(buf, "next boot"), buf);

    slots_t u;
    slots_init(&u);
    slots_begin_update(&u, SLOT_B, "3.1.0", 3);
    u.running = SLOT_B;
    slots_boot_attempt(&u);
    ok("an unconfirmed slot says so, with the attempts left",
       console_slot_line(&u, buf, sizeof(buf)) > 0 &&
       strstr(buf, "UNCONFIRMED") && strstr(buf, "2 boot attempt"), buf);
}

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/firex-phase8-%d", (int)getpid());
    if (mkdir(g_dir, 0700) != 0) { perror(g_dir); return 1; }
    mkdir(P("pkgroot"), 0755);

    test_bundles();
    test_slots();
    test_packages();
    test_console();

    printf("\n%d passed, %d failed\n", pass, fail);

    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", g_dir);
    if (system(rm) != 0) fprintf(stderr, "warning: %s was left behind\n", g_dir);
    return fail ? 1 : 0;
}
