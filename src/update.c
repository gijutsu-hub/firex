/*
 * Signed update bundles.
 *
 * The verifier is the only thing standing between a downloaded file and
 * the root filesystem the appliance boots next, so it is written to fail
 * closed: every error path returns non-zero with a reason, nothing is
 * written until all checks pass, and the signature is computed over a
 * canonical string this file builds, never over bytes taken from the
 * untrusted header.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "update.h"
#include "brand.h"

#define ERRF(e, n, ...) do { if (e && n) snprintf(e, n, __VA_ARGS__); } while (0)

/* ── base64 ─────────────────────────────────────────────────── */

static int b64_enc(const unsigned char *raw, size_t n, char *out, size_t outlen) {
    /* 4 characters per 3 bytes, rounded up, plus the NUL. */
    size_t need = ((n + 2) / 3) * 4 + 1;
    if (outlen < need) return -1;
    int w = EVP_EncodeBlock((unsigned char *)out, raw, (int)n);
    if (w < 0) return -1;
    out[w] = '\0';
    return 0;
}

/*
 * EVP_DecodeBlock rounds its output up to a multiple of three and cannot
 * tell us how many of those bytes were padding, so the caller states the
 * length it expects and we check the encoding is exactly that long.
 */
static int b64_dec(const char *in, unsigned char *out, size_t want) {
    size_t enc = ((want + 2) / 3) * 4;
    if (strlen(in) != enc) return -1;
    unsigned char buf[256];
    size_t rounded = ((want + 2) / 3) * 3;
    if (rounded > sizeof(buf)) return -1;
    int w = EVP_DecodeBlock(buf, (const unsigned char *)in, (int)enc);
    if (w < 0 || (size_t)w != rounded) return -1;
    memcpy(out, buf, want);
    return 0;
}

/* ── digests ────────────────────────────────────────────────── */

static void hexify(const unsigned char *raw, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = h[raw[i] >> 4];
        out[i * 2 + 1] = h[raw[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/*
 * SHA-256 over a byte range of an open file. Used for the payload, which
 * is far too large to hold in memory.
 */
static int sha256_range(FILE *f, long off, uint64_t len, char *hex) {
    if (fseek(f, off, SEEK_SET) != 0) return -1;

    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) return -1;
    if (EVP_DigestInit_ex(c, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(c);
        return -1;
    }

    unsigned char buf[65536];
    uint64_t left = len;
    while (left > 0) {
        size_t want = left > sizeof(buf) ? sizeof(buf) : (size_t)left;
        size_t got  = fread(buf, 1, want, f);
        if (got == 0) { EVP_MD_CTX_free(c); return -1; }
        EVP_DigestUpdate(c, buf, got);
        left -= got;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;
    int rc = EVP_DigestFinal_ex(c, md, &mdlen);
    EVP_MD_CTX_free(c);
    if (rc != 1 || mdlen != 32) return -1;

    hexify(md, 32, hex);
    return 0;
}

void upd_key_id(const unsigned char *pub, char *out) {
    unsigned char md[32];
    unsigned int  n = sizeof(md);
    EVP_Digest(pub, UPD_KEY_LEN, md, &n, EVP_sha256(), NULL);
    hexify(md, 8, out);
}

/* ── keys ───────────────────────────────────────────────────── */

int upd_keygen(char *priv_b64, char *pub_b64) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (!k) return -1;

    unsigned char priv[UPD_KEY_LEN], pub[UPD_KEY_LEN];
    size_t pl = sizeof(priv), ql = sizeof(pub);
    int rc = -1;

    if (EVP_PKEY_get_raw_private_key(k, priv, &pl) == 1 && pl == UPD_KEY_LEN &&
        EVP_PKEY_get_raw_public_key(k, pub, &ql)  == 1 && ql == UPD_KEY_LEN &&
        b64_enc(priv, pl, priv_b64, UPD_B64_LEN) == 0 &&
        b64_enc(pub,  ql, pub_b64,  UPD_B64_LEN) == 0)
        rc = 0;

    OPENSSL_cleanse(priv, sizeof(priv));
    EVP_PKEY_free(k);
    return rc;
}

int upd_keyid_from_b64(const char *pub_b64, char *out) {
    unsigned char pub[UPD_KEY_LEN];
    if (!pub_b64 || b64_dec(pub_b64, pub, UPD_KEY_LEN) != 0) return -1;
    upd_key_id(pub, out);
    return 0;
}

/* ── keyring ────────────────────────────────────────────────── */

int upd_keyring_add(upd_keyring_t *r, const unsigned char *pub, const char *comment) {
    if (!r || r->count >= UPD_MAX_KEYS) return -1;
    upd_key_t *k = &r->key[r->count];
    memcpy(k->key, pub, UPD_KEY_LEN);
    upd_key_id(pub, k->id);
    snprintf(k->comment, sizeof(k->comment), "%s", comment ? comment : "");
    r->count++;
    return 0;
}

const upd_key_t *upd_keyring_find(const upd_keyring_t *r, const char *keyid) {
    if (!r || !keyid) return NULL;
    for (int i = 0; i < r->count; i++)
        if (strcmp(r->key[i].id, keyid) == 0) return &r->key[i];
    return NULL;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
                     e[-1] == ' '  || e[-1] == '\t')) *--e = '\0';
    return s;
}

int upd_keyring_load(upd_keyring_t *r, const char *path, char *err, size_t errlen) {
    if (!r) return -1;
    memset(r, 0, sizeof(*r));

    FILE *f = fopen(path, "r");
    if (!f) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }

    char line[512];
    int  lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = trim(line);
        if (!*s || *s == '#') continue;

        /* "<base64 key> <optional comment>" */
        char *sp = strchr(s, ' ');
        char *comment = "";
        if (sp) { *sp = '\0'; comment = trim(sp + 1); }

        unsigned char pub[UPD_KEY_LEN];
        if (b64_dec(s, pub, UPD_KEY_LEN) != 0) {
            ERRF(err, errlen, "%s:%d: not a valid %d-byte base64 key",
                 path, lineno, UPD_KEY_LEN);
            fclose(f);
            return -1;
        }
        if (upd_keyring_add(r, pub, comment) != 0) {
            ERRF(err, errlen, "%s:%d: more than %d keys", path, lineno, UPD_MAX_KEYS);
            fclose(f);
            return -1;
        }
    }
    fclose(f);

    if (r->count == 0) {
        ERRF(err, errlen, "%s: no keys in the keyring", path);
        return -1;
    }
    return 0;
}

/* ── versions ───────────────────────────────────────────────── */

/*
 * Numeric component comparison, so 3.10.0 sorts above 3.9.0 where a
 * strcmp would put it below. Missing components count as zero, which
 * makes "3.1" and "3.1.0" equal.
 */
int upd_version_cmp(const char *a, const char *b) {
    while (*a || *b) {
        long va = 0, vb = 0;
        while (*a >= '0' && *a <= '9') va = va * 10 + (*a++ - '0');
        while (*b >= '0' && *b <= '9') vb = vb * 10 + (*b++ - '0');
        if (va != vb) return va < vb ? -1 : 1;
        if (*a == '.') a++;
        if (*b == '.') b++;
        if (!*a && !*b) break;
        /* Anything that is not a digit or a dot ends the comparison. */
        if ((*a && (*a < '0' || *a > '9')) || (*b && (*b < '0' || *b > '9')))
            break;
    }
    return 0;
}

/* ── canonical signed material ──────────────────────────────── */

static const char *kind_name(upd_kind_t k) {
    return k == UPD_KIND_PACKAGE ? "package" : "image";
}

int upd_signed_material(const upd_meta_t *m, char *out, size_t outlen) {
    int n = snprintf(out, outlen,
                     "firex-update-v1\n"
                     "kind=%s\n"
                     "name=%s\n"
                     "version=%s\n"
                     "build=%s\n"
                     "arch=%s\n"
                     "size=%llu\n"
                     "sha256=%s\n"
                     "requires=%s\n"
                     "description=%s\n",
                     kind_name(m->kind), m->name, m->version, m->build,
                     m->arch, (unsigned long long)m->size, m->sha256,
                     m->requires, m->description);
    if (n < 0 || (size_t)n >= outlen) return -1;
    return n;
}

/* ── creating a bundle ──────────────────────────────────────── */

int upd_bundle_create(const char *payload_path, upd_meta_t *meta,
                      const char *priv_b64, const char *out_path,
                      char *err, size_t errlen) {
    if (!meta || !priv_b64 || !payload_path || !out_path) return -1;

    unsigned char priv[UPD_KEY_LEN];
    if (b64_dec(priv_b64, priv, UPD_KEY_LEN) != 0) {
        ERRF(err, errlen, "the signing key is not %d base64 bytes", UPD_KEY_LEN);
        return -1;
    }

    FILE *pf = fopen(payload_path, "rb");
    if (!pf) {
        ERRF(err, errlen, "%s: %s", payload_path, strerror(errno));
        OPENSSL_cleanse(priv, sizeof(priv));
        return -1;
    }
    if (fseek(pf, 0, SEEK_END) != 0) {
        ERRF(err, errlen, "%s: not a seekable file", payload_path);
        fclose(pf); OPENSSL_cleanse(priv, sizeof(priv));
        return -1;
    }
    long plen = ftell(pf);
    if (plen <= 0) {
        ERRF(err, errlen, "%s: empty payload", payload_path);
        fclose(pf); OPENSSL_cleanse(priv, sizeof(priv));
        return -1;
    }
    meta->size = (uint64_t)plen;

    if (sha256_range(pf, 0, meta->size, meta->sha256) != 0) {
        ERRF(err, errlen, "%s: could not digest the payload", payload_path);
        fclose(pf); OPENSSL_cleanse(priv, sizeof(priv));
        return -1;
    }

    if (!meta->arch[0]) snprintf(meta->arch, sizeof(meta->arch), "x86_64");
    if (!meta->name[0]) snprintf(meta->name, sizeof(meta->name), "firex");

    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                               priv, UPD_KEY_LEN);
    OPENSSL_cleanse(priv, sizeof(priv));
    if (!k) {
        ERRF(err, errlen, "the signing key was rejected by OpenSSL");
        fclose(pf);
        return -1;
    }

    unsigned char pub[UPD_KEY_LEN];
    size_t ql = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(k, pub, &ql) != 1 || ql != UPD_KEY_LEN) {
        ERRF(err, errlen, "could not derive the public key");
        EVP_PKEY_free(k); fclose(pf);
        return -1;
    }
    upd_key_id(pub, meta->signer);

    char material[UPD_MAX_HEADER];
    int mlen = upd_signed_material(meta, material, sizeof(material));
    if (mlen < 0) {
        ERRF(err, errlen, "the bundle metadata is too large to sign");
        EVP_PKEY_free(k); fclose(pf);
        return -1;
    }

    unsigned char sig[UPD_SIG_LEN];
    size_t slen = sizeof(sig);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    int ok = mc &&
             EVP_DigestSignInit(mc, NULL, NULL, NULL, k) == 1 &&
             EVP_DigestSign(mc, sig, &slen, (const unsigned char *)material,
                            (size_t)mlen) == 1 &&
             slen == UPD_SIG_LEN;
    EVP_MD_CTX_free(mc);
    EVP_PKEY_free(k);
    if (!ok) {
        ERRF(err, errlen, "signing failed");
        fclose(pf);
        return -1;
    }
    if (b64_enc(sig, slen, meta->signature, sizeof(meta->signature)) != 0) {
        ERRF(err, errlen, "could not encode the signature");
        fclose(pf);
        return -1;
    }

    /* 0644: a bundle is meant to be copied around, and carries no secret. */
    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        ERRF(err, errlen, "%s: %s", out_path, strerror(errno));
        fclose(pf);
        return -1;
    }
    FILE *of = fdopen(fd, "wb");
    if (!of) {
        ERRF(err, errlen, "%s: %s", out_path, strerror(errno));
        close(fd); fclose(pf);
        return -1;
    }

    fprintf(of,
            "%s\n"
            "kind: %s\n"
            "name: %s\n"
            "version: %s\n"
            "build: %s\n"
            "arch: %s\n"
            "size: %llu\n"
            "sha256: %s\n"
            "requires: %s\n"
            "description: %s\n"
            "signer: %s\n"
            "signature: %s\n"
            "%s\n",
            UPD_MAGIC, kind_name(meta->kind), meta->name, meta->version,
            meta->build, meta->arch, (unsigned long long)meta->size,
            meta->sha256, meta->requires, meta->description,
            meta->signer, meta->signature, UPD_SEP);

    meta->payload_offset = ftell(of);

    if (fseek(pf, 0, SEEK_SET) != 0) {
        ERRF(err, errlen, "%s: rewind failed", payload_path);
        fclose(of); fclose(pf);
        return -1;
    }
    unsigned char buf[65536];
    uint64_t left = meta->size;
    while (left > 0) {
        size_t want = left > sizeof(buf) ? sizeof(buf) : (size_t)left;
        size_t got  = fread(buf, 1, want, pf);
        if (got == 0 || fwrite(buf, 1, got, of) != got) {
            ERRF(err, errlen, "%s: short write", out_path);
            fclose(of); fclose(pf);
            return -1;
        }
        left -= got;
    }

    fclose(pf);
    if (fclose(of) != 0) {
        ERRF(err, errlen, "%s: %s", out_path, strerror(errno));
        return -1;
    }
    return 0;
}

/* ── reading a bundle ───────────────────────────────────────── */

static void set_field(upd_meta_t *m, const char *key, const char *val) {
    if      (!strcmp(key, "kind"))
        m->kind = !strcmp(val, "package") ? UPD_KIND_PACKAGE : UPD_KIND_IMAGE;
    else if (!strcmp(key, "name"))        snprintf(m->name, sizeof(m->name), "%s", val);
    else if (!strcmp(key, "version"))     snprintf(m->version, sizeof(m->version), "%s", val);
    else if (!strcmp(key, "build"))       snprintf(m->build, sizeof(m->build), "%s", val);
    else if (!strcmp(key, "arch"))        snprintf(m->arch, sizeof(m->arch), "%s", val);
    else if (!strcmp(key, "requires"))    snprintf(m->requires, sizeof(m->requires), "%s", val);
    else if (!strcmp(key, "description")) snprintf(m->description, sizeof(m->description), "%s", val);
    else if (!strcmp(key, "sha256"))      snprintf(m->sha256, sizeof(m->sha256), "%s", val);
    else if (!strcmp(key, "signer"))      snprintf(m->signer, sizeof(m->signer), "%s", val);
    else if (!strcmp(key, "signature"))   snprintf(m->signature, sizeof(m->signature), "%s", val);
}

int upd_bundle_header(const char *path, upd_meta_t *meta, char *err, size_t errlen) {
    if (!meta) return -1;
    memset(meta, 0, sizeof(*meta));

    FILE *f = fopen(path, "rb");
    if (!f) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }

    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        ERRF(err, errlen, "%s: empty file", path);
        fclose(f);
        return -1;
    }
    trim(line);
    if (strcmp(line, UPD_MAGIC) != 0) {
        ERRF(err, errlen, "%s: not a %s bundle (bad magic)", path, BRAND_PRODUCT);
        fclose(f);
        return -1;
    }

    /*
     * Duplicate keys are refused rather than resolved last-wins. The
     * signature would catch the mismatch anyway, but a header that says
     * two different things about itself is not one to interpret: the
     * config parser learned the same lesson.
     */
    char seen[24][32];
    int  nseen = 0;

    bool saw_sep = false;
    long consumed = (long)strlen(UPD_MAGIC) + 1;
    while (fgets(line, sizeof(line), f)) {
        consumed = ftell(f);
        if (consumed > UPD_MAX_HEADER) {
            ERRF(err, errlen, "%s: header is larger than %d bytes",
                 path, UPD_MAX_HEADER);
            fclose(f);
            return -1;
        }
        char *s = trim(line);
        if (!strcmp(s, UPD_SEP)) { saw_sep = true; break; }
        if (!*s || *s == '#') continue;

        char *colon = strchr(s, ':');
        if (!colon) {
            ERRF(err, errlen, "%s: header line without a key: %.40s", path, s);
            fclose(f);
            return -1;
        }
        *colon = '\0';
        char *key = trim(s);

        for (int i = 0; i < nseen; i++) {
            if (strcmp(seen[i], key) == 0) {
                ERRF(err, errlen, "%s: the header sets '%s' twice", path, key);
                fclose(f);
                return -1;
            }
        }
        if (nseen < (int)(sizeof(seen) / sizeof(seen[0])))
            snprintf(seen[nseen++], sizeof(seen[0]), "%s", key);

        set_field(meta, key, trim(colon + 1));
    }

    if (!saw_sep) {
        ERRF(err, errlen, "%s: header has no '%s' separator", path, UPD_SEP);
        fclose(f);
        return -1;
    }
    meta->payload_offset = ftell(f);

    /* size has no setter above: it is the one numeric field, parsed here
     * so a non-numeric value is an error rather than a silent zero. */
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    char hdr[UPD_MAX_HEADER];
    size_t hn = fread(hdr, 1, sizeof(hdr) - 1, f);
    hdr[hn] = '\0';
    fclose(f);

    const char *sz = strstr(hdr, "\nsize:");
    if (!sz) {
        ERRF(err, errlen, "%s: the header has no size field", path);
        return -1;
    }
    char *endp = NULL;
    unsigned long long v = strtoull(sz + 6, &endp, 10);
    if (endp == sz + 6) {
        ERRF(err, errlen, "%s: the size field is not a number", path);
        return -1;
    }
    meta->size = (uint64_t)v;

    if (!meta->version[0]) {
        ERRF(err, errlen, "%s: the header has no version", path);
        return -1;
    }
    if (strlen(meta->sha256) != 64) {
        ERRF(err, errlen, "%s: the sha256 field is not 64 hex characters", path);
        return -1;
    }
    if (!meta->signer[0] || !meta->signature[0]) {
        ERRF(err, errlen, "%s: the bundle is not signed", path);
        return -1;
    }
    return 0;
}

int upd_bundle_verify(const char *path, const upd_keyring_t *ring,
                      const char *running_version,
                      upd_meta_t *meta, char *err, size_t errlen) {
    upd_meta_t local;
    if (!meta) meta = &local;

    if (upd_bundle_header(path, meta, err, errlen) != 0) return -1;

    if (!ring || ring->count == 0) {
        ERRF(err, errlen, "no trusted keys are configured; refusing the bundle");
        return -1;
    }
    const upd_key_t *k = upd_keyring_find(ring, meta->signer);
    if (!k) {
        ERRF(err, errlen, "signed by unknown key %s", meta->signer);
        return -1;
    }

    unsigned char sig[UPD_SIG_LEN];
    if (b64_dec(meta->signature, sig, UPD_SIG_LEN) != 0) {
        ERRF(err, errlen, "the signature is not %d base64 bytes", UPD_SIG_LEN);
        return -1;
    }

    char material[UPD_MAX_HEADER];
    int mlen = upd_signed_material(meta, material, sizeof(material));
    if (mlen < 0) {
        ERRF(err, errlen, "the bundle metadata is too large to verify");
        return -1;
    }

    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                               k->key, UPD_KEY_LEN);
    if (!pk) { ERRF(err, errlen, "the trusted key could not be loaded"); return -1; }
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    int ok = mc &&
             EVP_DigestVerifyInit(mc, NULL, NULL, NULL, pk) == 1 &&
             EVP_DigestVerify(mc, sig, UPD_SIG_LEN,
                              (const unsigned char *)material, (size_t)mlen) == 1;
    EVP_MD_CTX_free(mc);
    EVP_PKEY_free(pk);
    if (!ok) {
        ERRF(err, errlen, "the signature does not match the bundle metadata");
        return -1;
    }

    /* The signature covers the payload's digest, so the payload itself is
     * only trustworthy once that digest is confirmed against the bytes. */
    FILE *f = fopen(path, "rb");
    if (!f) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    if (fseek(f, 0, SEEK_END) != 0) {
        ERRF(err, errlen, "%s: not a seekable file", path);
        fclose(f);
        return -1;
    }
    long total = ftell(f);
    uint64_t have = (total > meta->payload_offset)
                    ? (uint64_t)(total - meta->payload_offset) : 0;
    if (have != meta->size) {
        ERRF(err, errlen, "payload is %llu bytes, the header claims %llu",
             (unsigned long long)have, (unsigned long long)meta->size);
        fclose(f);
        return -1;
    }

    char digest[UPD_SHA_HEX];
    int rc = sha256_range(f, meta->payload_offset, meta->size, digest);
    fclose(f);
    if (rc != 0) {
        ERRF(err, errlen, "%s: could not digest the payload", path);
        return -1;
    }
    if (strcmp(digest, meta->sha256) != 0) {
        ERRF(err, errlen, "payload digest %.16s... does not match the signed %.16s...",
             digest, meta->sha256);
        return -1;
    }

    if (running_version && meta->requires[0] &&
        upd_version_cmp(running_version, meta->requires) < 0) {
        ERRF(err, errlen, "needs %s or newer; this system runs %s",
             meta->requires, running_version);
        return -1;
    }
    return 0;
}

int upd_bundle_extract(const char *path, const upd_keyring_t *ring,
                       const char *out_path, char *err, size_t errlen) {
    upd_meta_t m;
    if (upd_bundle_verify(path, ring, NULL, &m, err, errlen) != 0) return -1;

    FILE *in = fopen(path, "rb");
    if (!in) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    if (fseek(in, m.payload_offset, SEEK_SET) != 0) {
        ERRF(err, errlen, "%s: seek to the payload failed", path);
        fclose(in);
        return -1;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        ERRF(err, errlen, "%s: %s", out_path, strerror(errno));
        fclose(in);
        return -1;
    }

    unsigned char buf[65536];
    uint64_t left = m.size;
    while (left > 0) {
        size_t want = left > sizeof(buf) ? sizeof(buf) : (size_t)left;
        size_t got  = fread(buf, 1, want, in);
        if (got == 0 || fwrite(buf, 1, got, out) != got) {
            ERRF(err, errlen, "%s: short write", out_path);
            fclose(in); fclose(out);
            unlink(out_path);
            return -1;
        }
        left -= got;
    }
    fclose(in);
    if (fclose(out) != 0) {
        ERRF(err, errlen, "%s: %s", out_path, strerror(errno));
        unlink(out_path);
        return -1;
    }
    return 0;
}
