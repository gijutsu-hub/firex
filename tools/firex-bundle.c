/*
 * firex-bundle -- creates and inspects signed update bundles.
 *
 * This runs on a build host that holds the signing key. It is deliberately
 * not installed on the appliance: an appliance that can sign its own
 * updates has no update signing to speak of.
 *
 *   firex-bundle keygen  --out firex-signing
 *   firex-bundle sign    --in rootfs.img --out firex-3.1.0.fxu \
 *                        --key firex-signing --version 3.1.0
 *   firex-bundle show    firex-3.1.0.fxu
 *   firex-bundle verify  firex-3.1.0.fxu --keyring firex-signing.pub
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "update.h"
#include "brand.h"

static int usage(void) {
    printf("%s bundle tool (%s %s)\n\n", BRAND_PRODUCT, BRAND_PRODUCT, BRAND_VERSION);
    printf("  firex-bundle keygen --out BASE\n");
    printf("      writes BASE (private, 0600) and BASE.pub (keyring line)\n\n");
    printf("  firex-bundle sign --in FILE --out BUNDLE --key PRIVATE \\\n");
    printf("      --version V [--kind image|package] [--name N]\n");
    printf("      [--requires V] [--arch A] [--description TEXT]\n\n");
    printf("  firex-bundle show BUNDLE\n");
    printf("      prints the header without verifying anything\n\n");
    printf("  firex-bundle verify BUNDLE --keyring FILE [--running V]\n");
    printf("      full signature and payload check\n\n");
    return 1;
}

static char *slurp_key(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    static char buf[UPD_B64_LEN];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return NULL; }
    fclose(f);
    char *e = buf + strlen(buf);
    while (e > buf && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) *--e = '\0';
    return buf;
}

static const char *arg(int argc, char **argv, const char *name, const char *def) {
    for (int i = 2; i + 1 < argc; i++)
        if (!strcmp(argv[i], name)) return argv[i + 1];
    return def;
}

static void print_meta(const upd_meta_t *m) {
    printf("  kind         %s\n", m->kind == UPD_KIND_PACKAGE ? "package" : "image");
    printf("  name         %s\n", m->name);
    printf("  version      %s\n", m->version);
    printf("  build        %s\n", m->build);
    printf("  arch         %s\n", m->arch);
    printf("  size         %llu bytes\n", (unsigned long long)m->size);
    printf("  sha256       %s\n", m->sha256);
    if (m->requires[0])    printf("  requires     %s or newer\n", m->requires);
    if (m->description[0]) printf("  description  %s\n", m->description);
    printf("  signer       %s\n", m->signer);
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    const char *cmd = argv[1];
    char err[512] = "";

    if (!strcmp(cmd, "keygen")) {
        const char *base = arg(argc, argv, "--out", NULL);
        if (!base) return usage();

        char priv[UPD_B64_LEN], pub[UPD_B64_LEN];
        if (upd_keygen(priv, pub) != 0) {
            fprintf(stderr, "key generation failed\n");
            return 1;
        }

        /* 0600 from the moment it exists: a signing key that is briefly
         * world-readable has been world-readable. */
        int fd = open(base, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) { perror(base); return 1; }
        dprintf(fd, "%s\n", priv);
        close(fd);

        char pubpath[512];
        snprintf(pubpath, sizeof(pubpath), "%s.pub", base);
        FILE *pf = fopen(pubpath, "w");
        if (!pf) { perror(pubpath); return 1; }

        /* The key id comes back by loading the keyring line we just wrote,
         * which also proves the line is one the appliance can parse. */
        char id[UPD_KEYID_LEN] = "";
        upd_keyring_t r;
        memset(&r, 0, sizeof(r));
        fprintf(pf, "# %s update signing key, generated %ld\n",
                BRAND_PRODUCT, (long)time(NULL));
        fprintf(pf, "%s %s build key\n", pub, BRAND_PRODUCT);
        fclose(pf);

        if (upd_keyring_load(&r, pubpath, err, sizeof(err)) == 0 && r.count == 1)
            snprintf(id, sizeof(id), "%s", r.key[0].id);

        printf("private key  %s   (0600, keep it off the appliance)\n", base);
        printf("keyring line %s\n", pubpath);
        printf("key id       %s\n", id);
        return 0;
    }

    if (!strcmp(cmd, "sign")) {
        const char *in   = arg(argc, argv, "--in", NULL);
        const char *out  = arg(argc, argv, "--out", NULL);
        const char *key  = arg(argc, argv, "--key", NULL);
        const char *ver  = arg(argc, argv, "--version", NULL);
        if (!in || !out || !key || !ver) return usage();

        upd_meta_t m;
        memset(&m, 0, sizeof(m));
        const char *kind = arg(argc, argv, "--kind", "image");
        m.kind = !strcmp(kind, "package") ? UPD_KIND_PACKAGE : UPD_KIND_IMAGE;
        snprintf(m.name,     sizeof(m.name),     "%s", arg(argc, argv, "--name", "firex"));
        snprintf(m.version,  sizeof(m.version),  "%s", ver);
        snprintf(m.arch,     sizeof(m.arch),     "%s", arg(argc, argv, "--arch", "x86_64"));
        snprintf(m.requires, sizeof(m.requires), "%s", arg(argc, argv, "--requires", ""));
        snprintf(m.description, sizeof(m.description), "%s",
                 arg(argc, argv, "--description", ""));

        time_t now = time(NULL);
        struct tm tmv;
        gmtime_r(&now, &tmv);
        strftime(m.build, sizeof(m.build), "%Y-%m-%dT%H:%M:%SZ", &tmv);

        char *priv = slurp_key(key);
        if (!priv) return 1;

        if (upd_bundle_create(in, &m, priv, out, err, sizeof(err)) != 0) {
            fprintf(stderr, "sign: %s\n", err);
            return 1;
        }
        printf("wrote %s\n", out);
        print_meta(&m);
        return 0;
    }

    if (!strcmp(cmd, "show")) {
        if (argc < 3) return usage();
        upd_meta_t m;
        if (upd_bundle_header(argv[2], &m, err, sizeof(err)) != 0) {
            fprintf(stderr, "show: %s\n", err);
            return 1;
        }
        printf("%s claims:\n", argv[2]);
        print_meta(&m);
        printf("\n  Nothing above has been verified. Run 'verify'.\n");
        return 0;
    }

    if (!strcmp(cmd, "verify")) {
        if (argc < 3) return usage();
        const char *kr  = arg(argc, argv, "--keyring", NULL);
        const char *run = arg(argc, argv, "--running", NULL);
        if (!kr) return usage();

        upd_keyring_t r;
        if (upd_keyring_load(&r, kr, err, sizeof(err)) != 0) {
            fprintf(stderr, "keyring: %s\n", err);
            return 1;
        }
        upd_meta_t m;
        if (upd_bundle_verify(argv[2], &r, run, &m, err, sizeof(err)) != 0) {
            fprintf(stderr, "REJECTED: %s\n", err);
            return 2;
        }
        printf("%s verified against %d trusted key(s):\n", argv[2], r.count);
        print_meta(&m);
        return 0;
    }

    return usage();
}
