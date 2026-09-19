/* SPDX-License-Identifier: GPL-3.0-or-later */
/* P0-9 churn driver: provider load/unload generation windows as oracle.
 * Usage: churn -n N -gens G [-reuse]
 * Fresh OSSL_LIB_CTX per phase and per generation (default ctx untouched,
 * so every unload truly unmaps). GO: 1 gen in ctxA (query triggers +
 * CALLBACKS). GO2: refetch in ctxB (REFETCH2=ok). GO3: MARK GO3 into the
 * counter file, GO3START, then G gens; each prints GEN with (prov, ino,
 * dev, base, no_store) + CHURNDONE. -reuse: ADDR_NO_RANDOMIZE, second
 * half of gens use the decoy provider; OVERLAP=1 iff first decoy base ==
 * last spike base (address-reuse cell needs overlapping VAs).
 * stdout: exactly "%ld\n" (N, evp_driver-compatible). Exit 2 on
 * provider problems. EOF on stdin exits 0 (one-shot compat). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

static unsigned long long now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull
        + (unsigned long long)ts.tv_nsec;
}

static unsigned char input[1024];

/* Serial digest loop (evp_driver run_digest_1, updates=1, no times). */
static int run_ops(EVP_MD *md, long n)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];
    unsigned int outl = 0;
    long i;

    if (ctx == NULL)
        return 1;
    for (i = 0; i < n; i++) {
        if (!EVP_DigestInit_ex2(ctx, md, NULL)
            || !EVP_DigestUpdate(ctx, input, sizeof input)
            || !EVP_DigestFinal_ex(ctx, out, &outl)) {
            fprintf(stderr, "churn: digest iter %ld failed\n", i);
            EVP_MD_CTX_free(ctx);
            return 1;
        }
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

/* Direct query_operation call (run_sign-style) to observe no_store. */
static int query_nostore(const char *path, int op)
{
    void *h;
    const OSSL_DISPATCH *out = NULL, *d;
    void *provctx = NULL;
    int no_store = -1;
    int (*p_init)(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *,
                  const OSSL_DISPATCH **, void **);
    const OSSL_ALGORITHM *(*query)(void *, int, int *);

    /* Explicit load + paired close: net-zero refcount regardless of
     * RTLD_NOLOAD's murky ownership (an NOLOAD leak would pin the
     * mapping and make churn vacuous). */
    h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL)
        return -1;
    p_init = (int (*)(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *,
                      const OSSL_DISPATCH **, void **))
        dlsym(h, "OSSL_provider_init");
    if (p_init == NULL || !p_init(NULL, NULL, &out, &provctx)) {
        dlclose(h);
        return -1;
    }
    query = NULL;
    for (d = out; d->function_id != 0; d++) {
        if (d->function_id == OSSL_FUNC_PROVIDER_QUERY_OPERATION)
            query = (const OSSL_ALGORITHM *(*)(void *, int, int *))
                d->function;
    }
    if (query == NULL) {
        dlclose(h);
        return -1;
    }
    if (query(provctx, op, &no_store) == NULL) {
        dlclose(h);
        return -1;
    }
    dlclose(h);
    return no_store;
}

/* First mapping start of path in /proc/self/maps ("none" if unmapped). */
static void map_base(const char *path, char *base, size_t blen)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[1024];

    snprintf(base, blen, "none");
    if (f == NULL)
        return;
    while (fgets(line, sizeof line, f) != NULL) {
        char *p = strchr(line, '/');

        if (p != NULL && strncmp(p, path, strlen(path)) == 0
            && (p[strlen(path)] == '\n' || p[strlen(path)] == '\0'
                || p[strlen(path)] == ' ')) {
            char *dash = strchr(line, '-');

            if (dash != NULL) {
                *dash = '\0';
                snprintf(base, blen, "%s", line);
            }
            break;
        }
    }
    fclose(f);
}

/* One generation: fresh ctx, load, fetch, N ops, GEN line, unload. */
static int run_gen(const char *prov, const char *dig_name,
                   const char *sig_name, long n, long gen,
                   char *base_out, size_t base_len)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *p;
    EVP_MD *md;
    EVP_SIGNATURE *sig;
    char propquery[128], path[512], base[32];
    const char *moddir = getenv("OPENSSL_MODULES");
    struct stat st;
    unsigned long long open_t, close_t;
    int nd, ns;
    const char *n1, *n2;

    if (ctx == NULL)
        return 2;
    if (moddir == NULL || *moddir == '\0')
        moddir = "/tmp/spike";
    snprintf(path, sizeof path, "%s/%s.so", moddir, prov);
    snprintf(propquery, sizeof propquery, "provider=%s", prov);
    open_t = now_ns();
    p = OSSL_PROVIDER_load(ctx, prov);
    md = p != NULL ? EVP_MD_fetch(ctx, dig_name, propquery) : NULL;
    sig = p != NULL ? EVP_SIGNATURE_fetch(ctx, sig_name, propquery) : NULL;
    if (p == NULL || md == NULL || sig == NULL) {
        fprintf(stderr, "churn: gen %ld load/fetch failed\n", gen);
        OSSL_LIB_CTX_free(ctx);
        return 2;
    }
    n1 = OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md));
    n2 = OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(sig));
    if (strcmp(n1, prov) != 0 || strcmp(n2, prov) != 0) {
        fprintf(stderr, "churn: gen %ld wrong provider %s/%s\n", gen,
            n1, n2);
        EVP_MD_free(md);
        EVP_SIGNATURE_free(sig);
        OSSL_LIB_CTX_free(ctx);
        return 2;
    }
    if (run_ops(md, n) != 0) {
        EVP_MD_free(md);
        EVP_SIGNATURE_free(sig);
        OSSL_LIB_CTX_free(ctx);
        return 1;
    }
    nd = query_nostore(path, OSSL_OP_DIGEST);
    ns = query_nostore(path, OSSL_OP_SIGNATURE);
    map_base(path, base, sizeof base);
    EVP_MD_free(md);
    EVP_SIGNATURE_free(sig);
    if (!OSSL_PROVIDER_unload(p)) {
        fprintf(stderr, "churn: gen %ld unload failed\n", gen);
        OSSL_LIB_CTX_free(ctx);
        return 2;
    }
    OSSL_LIB_CTX_free(ctx);
    close_t = now_ns();
    if (stat(path, &st) != 0)
        return 2;
    fprintf(stderr, "GEN gen=%ld prov=%s ino=%llu dev=%llu base=%s "
        "ops=%ld open_t=%llu close_t=%llu nostore_d=%d nostore_s=%d\n",
        gen, prov, (unsigned long long)st.st_ino,
        (unsigned long long)st.st_dev, base, n, open_t, close_t, nd, ns);
    snprintf(base_out, base_len, "%s", base);
    return 0;
}

static int want_go(const char *what)
{
    char line[16];

    if (fgets(line, sizeof line, stdin) == NULL)
        exit(0);
    if (strcmp(line, "GO\n") != 0) {
        fprintf(stderr, "churn: want %s\n", what);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    long n = -1, gens = -1;
    int reuse = 0, i, rc;
    const char *prov, *dig_name, *sig_name;
    const char *decprov, *decdig, *decsig;
    char last_spike_base[32] = {0}, first_decoy_base[32] = {0};

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atol(argv[++i]);
        } else if (strcmp(argv[i], "-gens") == 0 && i + 1 < argc) {
            gens = atol(argv[++i]);
        } else if (strcmp(argv[i], "-reuse") == 0) {
            reuse = 1;
        } else {
            fprintf(stderr, "usage: churn -n N -gens G [-reuse]\n");
            return 1;
        }
    }
    if (n < 0 || gens < 1) {
        fprintf(stderr, "usage: churn -n N -gens G [-reuse]\n");
        return 1;
    }
    if (reuse && personality(ADDR_NO_RANDOMIZE | personality(0xffffffff))
        == -1)
        fprintf(stderr, "churn: WARN personality failed\n");
    prov = getenv("SPIKE_PROV");
    if (prov == NULL || *prov == '\0')
        prov = "spike";
    dig_name = getenv("SPIKE_DIGEST");
    if (dig_name == NULL || *dig_name == '\0')
        dig_name = "SPIKE-SHA";
    sig_name = getenv("SPIKE_SIG");
    if (sig_name == NULL || *sig_name == '\0')
        sig_name = "SPIKE-SIG";
    decprov = getenv("DECOY_PROV");
    if (decprov == NULL || *decprov == '\0')
        decprov = "decoy";
    decdig = getenv("DECOY_DIGEST");
    if (decdig == NULL || *decdig == '\0')
        decdig = "DECOY-SHA";
    decsig = getenv("DECOY_SIG");
    if (decsig == NULL || *decsig == '\0')
        decsig = "DECOY-SIG";
    memset(input, 0xA5, sizeof input);

    fprintf(stderr, "PID=%d\n", (int)getpid());
    if (want_go("GO") != 0)
        return 1;
    /* Phase 1 in a throwaway ctx (default ctx stays clean so GO3
     * unloads truly unmap). */
    {
        OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *p;
        EVP_MD *md;
        EVP_SIGNATURE *sig;
        char propquery[128];

        snprintf(propquery, sizeof propquery, "provider=%s", prov);
        p = ctx != NULL ? OSSL_PROVIDER_load(ctx, prov) : NULL;
        md = p != NULL ? EVP_MD_fetch(ctx, dig_name, propquery) : NULL;
        sig = p != NULL
            ? EVP_SIGNATURE_fetch(ctx, sig_name, propquery) : NULL;
        if (p == NULL || md == NULL || sig == NULL) {
            fprintf(stderr, "churn: phase-1 fetch failed\n");
            return 2;
        }
        fprintf(stderr, "provider[digest]=%s\nprovider[sign]=%s\n",
            OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)),
            OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(sig)));
        if (run_ops(md, n) != 0)
            return 1;
        EVP_MD_free(md);
        EVP_SIGNATURE_free(sig);
        OSSL_PROVIDER_unload(p);
        OSSL_LIB_CTX_free(ctx);
    }
    fprintf(stderr, "N=%ld\nCALLBACKS=%ld\n", n, 3L * n);
    printf("%ld\n", n);
    fflush(stdout);

    if (want_go("GO2") != 0)
        return 1;
    {
        OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *p;
        EVP_MD *md;
        EVP_SIGNATURE *sig;
        char propquery[128];

        snprintf(propquery, sizeof propquery, "provider=%s", prov);
        p = ctx != NULL ? OSSL_PROVIDER_load(ctx, prov) : NULL;
        md = p != NULL ? EVP_MD_fetch(ctx, dig_name, propquery) : NULL;
        sig = p != NULL
            ? EVP_SIGNATURE_fetch(ctx, sig_name, propquery) : NULL;
        if (p == NULL || md == NULL || sig == NULL) {
            fprintf(stderr, "churn: ctx2 refetch failed\n");
            return 2;
        }
        EVP_MD_free(md);
        EVP_SIGNATURE_free(sig);
        OSSL_PROVIDER_unload(p);
        OSSL_LIB_CTX_free(ctx);
        fprintf(stderr, "REFETCH2=ok\n");
    }

    if (want_go("GO3") != 0)
        return 1;
    {
        const char *cpath = getenv("SPIKE_COUNTER_FILE");
        FILE *cf;

        if (cpath == NULL || *cpath == '\0')
            cpath = "/tmp/spike-counters.log";
        cf = fopen(cpath, "a");
        if (cf == NULL) {
            fprintf(stderr, "churn: counter file unwritable\n");
            return 1;
        }
        fprintf(cf, "MARK GO3\n");
        fclose(cf);
    }
    fprintf(stderr, "GO3START t_ns=%llu\n", now_ns());
    for (i = 0; i < gens; i++) {
        int swapped = reuse && i >= gens / 2;
        const char *p = swapped ? decprov : prov;
        const char *d = swapped ? decdig : dig_name;
        const char *s = swapped ? decsig : sig_name;
        char base[32];

        rc = run_gen(p, d, s, n, i, base, sizeof base);
        if (rc != 0)
            return rc;
        if (reuse && i == gens / 2 - 1)
            snprintf(last_spike_base, sizeof last_spike_base, "%s",
                base);
        if (reuse && i == gens / 2)
            snprintf(first_decoy_base, sizeof first_decoy_base, "%s",
                base);
    }
    if (reuse) {
        fprintf(stderr, "OVERLAP=%d spike_base=%s decoy_base=%s\n",
            strcmp(last_spike_base, first_decoy_base) == 0
                && last_spike_base[0] != '\0'
                && strcmp(last_spike_base, "none") != 0 ? 1 : 0,
            last_spike_base, first_decoy_base);
    }
    fprintf(stderr, "CHURNDONE gens=%ld ops=%ld\n", gens, gens * n);
    want_go("GO4-or-EOF");
    return 0;
}
