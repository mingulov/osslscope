/* P0-3 EVP driver: deterministic dispatch-callback ground truth.
 * Usage: echo GO | evp_driver -n N -alg {digest|sign}
 * stdout: exactly "%ld\n" with N. stderr: diagnostics (provider lines,
 * N=/CALLBACKS=, per-iteration times). Exit 2 on provider problems.
 *
 * Startup blocks on one stdin line (post-attach GO trigger, required by
 * P0-4), loads spike, and fetches SPIKE-SHA + SPIKE-SIG once each to fire
 * both M1 query triggers. Digest loop uses the EVP path; sign loop invokes
 * the query-returned SPIKE-SIG dispatch table directly (see PLAN P0-3).
 * A second GO line refetches both algs in a fresh libctx (P0-4 stage-2
 * retrigger) then blocks on stdin until EOF; EOF exits 0 (one-shot).
 * A third GO line (P0-6) re-runs the loop post-attach, prints LOOPDONE.
 * With -threads T (P0-7), the digest loop runs T threads x N/T iters.
 * With -updates K (P0-8), each digest iter does K 1KB updates over a
 * 16KB input (K=16: the 16KB/1KB flood). EVP_DRIVER_TIMES=1 prints
 * per-iter ns; =2 prints one PCT p50/p99/max/count line per run.
 * With -storm T (P0-13), GO3 instead runs T threads x 50 fresh-libctx
 * fetch pairs (concurrent query_operation storm for the harvest uretprobe
 * proof) and prints STORMDONE threads=T iters=50 fail=F.
 * Env: SPIKE_PROV (default spike), SPIKE_DIGEST (default SPIKE-SHA),
 * SPIKE_SIG (default SPIKE-SIG) select provider + fetched algs.
 * SPIKE_SIG="" skips the signature fetch (digest-only providers such as
 * legacy/alias). SPIKE_QUERY_ALL=1 fires the M2 re-query trigger for
 * inventory completeness: direct OSSL_PROVIDER_query_operation calls
 * for every op x SPIKE_QUERY_ROUNDS (default 256) on the loaded
 * provider + default + legacy after GO1 and in the GO2 fresh libctx
 * (P1 exit 2; one alg walked per query-return hit, 256/op covers the
 * BPF bound). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>

static unsigned long long now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull
        + (unsigned long long)ts.tv_nsec;
}

typedef void *(*sig_newctx_fn)(void *, const char *);
typedef void (*sig_freectx_fn)(void *);
typedef int (*sig_sign_init_fn)(void *, void *, const OSSL_PARAM *);
typedef int (*sig_sign_fn)(void *, unsigned char *, size_t *, size_t,
                           const unsigned char *, size_t);
typedef int (*sig_verify_init_fn)(void *, void *, const OSSL_PARAM *);
typedef int (*sig_verify_fn)(void *, const unsigned char *, size_t,
                             const unsigned char *, size_t);

struct sig_fns {
    sig_newctx_fn newctx;
    sig_freectx_fn freectx;
    sig_sign_init_fn sign_init;
    sig_sign_fn sign;
    sig_verify_init_fn verify_init;
    sig_verify_fn verify;
};

/* P0-13 storm: file-scope fetch params shared with worker threads. */
static const char *storm_prov;
static const char *storm_dig;
static const char *storm_sig;

/* P1 exit 2: inventory-completeness trigger. Harvest only observes ops
 * the target queries, one alg per query-return hit; direct
 * query_operation calls (public API, same function the harvest uprobe
 * attaches to) cover every op without an alg-name matrix. 256
 * rounds/op cover the BPF alg bound. */
static void query_all_rounds(OSSL_LIB_CTX *ctx, const char *prov)
{
    const char *targets[3];
    const char *er = getenv("SPIKE_QUERY_ROUNDS");
    int rounds = er != NULL ? atoi(er) : 256;
    int r, op, t;

    if (getenv("SPIKE_QUERY_ALL") == NULL)
        return;
    if (rounds < 1)
        rounds = 1;
    if (rounds > 1024)
        rounds = 1024;
    targets[0] = prov;
    targets[1] = "default";
    targets[2] = "legacy";
    for (t = 0; t < 3; t++) {
        OSSL_PROVIDER *p = OSSL_PROVIDER_load(ctx, targets[t]);

        if (p == NULL)
            continue;
        for (op = 1; op <= OSSL_OP__HIGHEST; op++) {
            for (r = 0; r < rounds; r++) {
                const OSSL_ALGORITHM *a;
                int no = 0;

                a = OSSL_PROVIDER_query_operation(p, op, &no);
                OSSL_PROVIDER_unquery_operation(p, op, a);
            }
        }
    }
    fprintf(stderr, "QUERYALL=ok rounds=%d\n", rounds);
}
static char storm_propquery[128];
static long storm_fail;
#define STORM_ITERS 50

static void *storm_worker(void *arg)
{
    int k;

    (void)arg;
    for (k = 0; k < STORM_ITERS; k++) {
        OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *p;
        EVP_MD *md;
        EVP_SIGNATURE *sig;

        if (ctx == NULL) {
            __sync_fetch_and_add(&storm_fail, 1);
            continue;
        }
        p = OSSL_PROVIDER_load(ctx, storm_prov);
        md = EVP_MD_fetch(ctx, storm_dig, storm_propquery);
        sig = EVP_SIGNATURE_fetch(ctx, storm_sig, storm_propquery);
        if (p == NULL || md == NULL || sig == NULL)
            __sync_fetch_and_add(&storm_fail, 1);
        EVP_MD_free(md);
        EVP_SIGNATURE_free(sig);
        OSSL_LIB_CTX_free(ctx);
    }
    return NULL;
}

static int run_storm(int threads)
{
    pthread_t *tids;
    int i;

    tids = calloc((size_t)threads, sizeof *tids);
    if (tids == NULL)
        return 1;
    for (i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], NULL, storm_worker, NULL) != 0) {
            free(tids);
            return 1;
        }
    }
    for (i = 0; i < threads; i++)
        pthread_join(tids[i], NULL);
    free(tids);
    fprintf(stderr, "STORMDONE threads=%d iters=%d fail=%ld\n",
        threads, STORM_ITERS, storm_fail);
    return storm_fail == 0 ? 0 : 2;
}

static const OSSL_DISPATCH *find_alg_dispatch(const OSSL_ALGORITHM *algs,
                                              const char *want)
{
    for (; algs->algorithm_names != NULL; algs++) {
        if (strcmp(algs->algorithm_names, want) == 0)
            return algs->implementation;
    }
    return NULL;
}

static void *find_fn(const OSSL_DISPATCH *d, int id)
{
    for (; d->function_id != 0; d++) {
        if (d->function_id == id)
            return (void *)d->function;
    }
    return NULL;
}

static unsigned char input[16384];

static int cmp_u64(const void *a, const void *b)
{
    unsigned long long x = *(const unsigned long long *)a;
    unsigned long long y = *(const unsigned long long *)b;

    return (x > y) - (x < y);
}

static int run_digest_1(EVP_MD *md, long n, int times, long tag, long updates)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];
    unsigned int outl = 0;
    unsigned long long *ts = NULL;
    long i, u;

    if (ctx == NULL)
        return 1;
    if (times == 2) {
        ts = malloc((size_t)n * sizeof *ts);
        if (ts == NULL) {
            EVP_MD_CTX_free(ctx);
            return 1;
        }
    }
    for (i = 0; i < n; i++) {
        unsigned long long t0 = times ? now_ns() : 0;

        if (!EVP_DigestInit_ex2(ctx, md, NULL)) {
            fprintf(stderr, "digest iter %ld init failed (tag %ld)\n", i, tag);
            free(ts);
            EVP_MD_CTX_free(ctx);
            return 1;
        }
        for (u = 0; u < updates; u++) {
            if (!EVP_DigestUpdate(ctx, input + u * 1024, 1024)) {
                fprintf(stderr, "digest iter %ld update %ld failed (tag %ld)\n",
                    i, u, tag);
                free(ts);
                EVP_MD_CTX_free(ctx);
                return 1;
            }
        }
        if (!EVP_DigestFinal_ex(ctx, out, &outl)) {
            fprintf(stderr, "digest iter %ld final failed (tag %ld)\n", i, tag);
            free(ts);
            EVP_MD_CTX_free(ctx);
            return 1;
        }
        if (times == 1)
            fprintf(stderr, "t[%ld]=%llu\n", i, now_ns() - t0);
        else if (times == 2)
            ts[i] = now_ns() - t0;
    }
    EVP_MD_CTX_free(ctx);
    if (times == 2) {
        qsort(ts, (size_t)n, sizeof *ts, cmp_u64);
        fprintf(stderr, "PCT tag=%ld p50=%llu p99=%llu max=%llu count=%ld\n",
            tag, ts[n / 2], ts[(n * 99) / 100], ts[n - 1], n);
    }
    free(ts);
    return 0;
}

struct digest_job {
    EVP_MD *md;
    long iters;
    int times;
    long tag;
    long updates;
    int fail;
};

static void *digest_worker(void *arg)
{
    struct digest_job *j = arg;

    if (run_digest_1(j->md, j->iters, j->times, j->tag, j->updates) != 0)
        j->fail = 1;
    return NULL;
}

/* threads<=1: the original serial loop. Else T threads x n/T iters with
 * per-thread contexts (P0-7 8-thread cell; n must split evenly). Total
 * executed callbacks are identical modulo per-thread ctx new/free, and
 * the counter-file oracle observes the same executions as eBPF. */
static int run_digest(EVP_MD *md, long n, int times, long threads,
                      long updates)
{
    if (threads > 1) {
        struct digest_job *jobs;
        pthread_t *tids;
        long i;

        if (n % threads != 0) {
            fprintf(stderr, "digest: n=%ld not divisible by threads=%ld\n",
                n, threads);
            return 1;
        }
        jobs = calloc((size_t)threads, sizeof *jobs);
        tids = calloc((size_t)threads, sizeof *tids);
        if (jobs == NULL || tids == NULL) {
            free(jobs);
            free(tids);
            return 1;
        }
        for (i = 0; i < threads; i++) {
            jobs[i].md = md;
            jobs[i].iters = n / threads;
            jobs[i].times = times;
            jobs[i].tag = i;
            jobs[i].updates = updates;
            if (pthread_create(&tids[i], NULL, digest_worker, &jobs[i])
                != 0) {
                free(jobs);
                free(tids);
                return 1;
            }
        }
        for (i = 0; i < threads; i++)
            pthread_join(tids[i], NULL);
        for (i = 0; i < threads; i++) {
            if (jobs[i].fail) {
                free(jobs);
                free(tids);
                return 1;
            }
        }
        /* Proof of threaded execution (3.0.x counts can't show it: no
         * per-thread ctx callbacks there). Asserted by exact-remote. */
        fprintf(stderr, "THREADS_ACTIVE=%ld\n", threads);
        free(jobs);
        free(tids);
    } else {
        if (run_digest_1(md, n, times, 0, updates) != 0)
            return 1;
    }
    fprintf(stderr, "N=%ld\nCALLBACKS=%ld\n", n, (2L + updates) * n);
    return 0;
}

static int run_sign(const char *prov, const char *sig_name, long n,
                    int times)
{
    const char *moddir = getenv("OPENSSL_MODULES");
    char path[512];
    void *h, *provctx = NULL;
    const OSSL_DISPATCH *out = NULL, *d;
    const OSSL_ALGORITHM *algs;
    struct sig_fns f;
    int no_store = 0;
    long i;
    int (*p_init)(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *,
                  const OSSL_DISPATCH **, void **);
    const OSSL_ALGORITHM *(*query)(void *, int, int *);

    if (moddir == NULL)
        moddir = "/tmp/spike";
    snprintf(path, sizeof path, "%s/%s.so", moddir, prov);
    /* NOLOAD: must reuse libcrypto's mapping (identical addresses). */
    h = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
    if (h == NULL) {
        fprintf(stderr, "dlopen NOLOAD failed: %s\n", dlerror());
        return 2;
    }
    p_init = (int (*)(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *,
                      const OSSL_DISPATCH **, void **))
        dlsym(h, "OSSL_provider_init");
    if (p_init == NULL || !p_init(NULL, NULL, &out, &provctx))
        return 2;
    query = NULL;
    for (d = out; d->function_id != 0; d++) {
        if (d->function_id == OSSL_FUNC_PROVIDER_QUERY_OPERATION)
            query = (const OSSL_ALGORITHM *(*)(void *, int, int *))
                d->function;
    }
    if (query == NULL)
        return 2;
    algs = query(provctx, OSSL_OP_SIGNATURE, &no_store);
    if (algs == NULL)
        return 2;
    d = find_alg_dispatch(algs, sig_name);
    if (d == NULL)
        return 2;
    f.newctx = find_fn(d, OSSL_FUNC_SIGNATURE_NEWCTX);
    f.freectx = find_fn(d, OSSL_FUNC_SIGNATURE_FREECTX);
    f.sign_init = find_fn(d, OSSL_FUNC_SIGNATURE_SIGN_INIT);
    f.sign = find_fn(d, OSSL_FUNC_SIGNATURE_SIGN);
    f.verify_init = find_fn(d, OSSL_FUNC_SIGNATURE_VERIFY_INIT);
    f.verify = find_fn(d, OSSL_FUNC_SIGNATURE_VERIFY);
    if (f.newctx == NULL || f.freectx == NULL || f.sign_init == NULL
        || f.sign == NULL || f.verify_init == NULL || f.verify == NULL)
        return 2;
    for (i = 0; i < n; i++) {
        unsigned long long t0 = times ? now_ns() : 0;
        unsigned char sigbuf[64];
        size_t siglen = 0;
        void *ctx = f.newctx(NULL, NULL);

        if (ctx == NULL
            || !f.sign_init(ctx, NULL, NULL)
            || !f.sign(ctx, sigbuf, &siglen, sizeof sigbuf,
                       input, sizeof input)
            || !f.verify_init(ctx, NULL, NULL)
            || !f.verify(ctx, sigbuf, siglen, input, sizeof input)) {
            fprintf(stderr, "sign iter %ld failed\n", i);
            return 1;
        }
        f.freectx(ctx);
        if (times)
            fprintf(stderr, "t[%ld]=%llu\n", i, now_ns() - t0);
    }
    fprintf(stderr, "N=%ld\nCALLBACKS=%ld\n", n, 6L * n);
    return 0;
}

int fallback_run(long n); /* P0-11: fallback_provider.c */

int main(int argc, char **argv)
{
    long n = -1;
    long storm = 0;
    long threads = 0;
    long updates = 1;
    int fallback = 0;
    const char *alg = NULL;
    const char *prov;
    const char *dig_name, *sig_name;
    const char *dig2_name, *sig2_name;
    char propquery[128];
    int i, times, rc;
    EVP_MD *md;
    EVP_SIGNATURE *sig;
    const char *n1, *n2;
    int want_sig;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atol(argv[++i]);
        } else if (strcmp(argv[i], "-alg") == 0 && i + 1 < argc) {
            alg = argv[++i];
        } else if (strcmp(argv[i], "-storm") == 0 && i + 1 < argc) {
            storm = atol(argv[++i]);
        } else if (strcmp(argv[i], "-threads") == 0 && i + 1 < argc) {
            threads = atol(argv[++i]);
        } else if (strcmp(argv[i], "-updates") == 0 && i + 1 < argc) {
            updates = atol(argv[++i]);
        } else if (strcmp(argv[i], "-fallback") == 0) {
            fallback = 1;
        } else {
            fprintf(stderr, "usage: evp_driver -n N -alg {digest|sign} [-storm T] [-threads T] [-updates K] [-fallback]\n");
            return 1;
        }
    }
    if (fallback) {
        int frc;

        if (n < 0) {
            fprintf(stderr, "usage: evp_driver -n N -fallback\n");
            return 1;
        }
        fprintf(stderr, "PID=%d\n", (int)getpid());
        {
            char line[16];

            if (fgets(line, sizeof line, stdin) == NULL
                || strcmp(line, "GO\n") != 0) {
                fprintf(stderr, "evp_driver: missing GO on stdin\n");
                return 1;
            }
        }
        frc = fallback_run(n);
        if (frc == 0)
            fprintf(stderr, "FALLBACKDONE ops=%ld\n", n);
        /* Linger until stdin EOF (sibling GO2/EOF protocol): the
         * harvester's settle window outlives the ~1s fallback burst,
         * and an exited target fails the pid pin (drain-end verify
         * races driver exit — settle must observe a live task). */
        {
            char line[16];

            while (fgets(line, sizeof line, stdin) != NULL) {
            }
        }
        return frc;
    }
    if (n < 0 || alg == NULL
        || (strcmp(alg, "digest") != 0 && strcmp(alg, "sign") != 0)) {
        fprintf(stderr, "usage: evp_driver -n N -alg {digest|sign} [-storm T] [-threads T] [-updates K] [-fallback]\n");
        return 1;
    }
    if (updates < 1 || updates > 16) {
        fprintf(stderr, "evp_driver: updates must be 1..16\n");
        return 1;
    }
    times = getenv("EVP_DRIVER_TIMES") != NULL
        ? atoi(getenv("EVP_DRIVER_TIMES")) : 0;

    /* Real pid for the harvester (coproc $DRV_PID may be a subshell). */
    fprintf(stderr, "PID=%d\n", (int)getpid());

    /* Post-attach GO trigger: block for one stdin line. */
    {
        char line[16];

        if (fgets(line, sizeof line, stdin) == NULL
            || strcmp(line, "GO\n") != 0) {
            fprintf(stderr, "evp_driver: missing GO on stdin\n");
            return 1;
        }
    }

    prov = getenv("SPIKE_PROV");
    if (prov == NULL || *prov == '\0')
        prov = "spike";
    dig_name = getenv("SPIKE_DIGEST");
    if (dig_name == NULL || *dig_name == '\0')
        dig_name = "SPIKE-SHA";
    sig_name = getenv("SPIKE_SIG");
    if (sig_name == NULL)
        sig_name = "SPIKE-SIG";
    want_sig = *sig_name != '\0';
    /* Second-alg names for the GO2 refetch (empty = skip): distinct
     * names miss the method store, forcing one more post-attach
     * query per op so GO2 alone covers multi-alg arrays (GO1 races
     * the stage-2 attach and is routinely missed — exit-1
     * hardening, 2026-09-17). */
    dig2_name = getenv("SPIKE_DIGEST2");
    if (dig2_name == NULL)
        dig2_name = "";
    sig2_name = getenv("SPIKE_SIG2");
    if (sig2_name == NULL)
        sig2_name = "";
    snprintf(propquery, sizeof propquery, "provider=%s", prov);
    storm_prov = prov;
    storm_dig = dig_name;
    storm_sig = sig_name;
    snprintf(storm_propquery, sizeof storm_propquery, "provider=%s", prov);
    if (!OSSL_PROVIDER_available(NULL, prov)
        && OSSL_PROVIDER_load(NULL, prov) == NULL) {
        fprintf(stderr, "evp_driver: %s provider unavailable\n", prov);
        return 2;
    }
    md = EVP_MD_fetch(NULL, dig_name, propquery);
    sig = want_sig ? EVP_SIGNATURE_fetch(NULL, sig_name, propquery) : NULL;
    if (md == NULL || (want_sig && sig == NULL)) {
        fprintf(stderr, "evp_driver: spike fetch failed\n");
        return 2;
    }
    n1 = OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md));
    fprintf(stderr, "provider[digest]=%s\n", n1);
    if (strcmp(n1, prov) != 0)
        return 2;
    if (want_sig) {
        n2 = OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(sig));
        fprintf(stderr, "provider[sign]=%s\n", n2);
        if (strcmp(n2, prov) != 0)
            return 2;
    }
    query_all_rounds(NULL, prov);

    memset(input, 0xA5, sizeof input);
    if (strcmp(alg, "digest") == 0)
        rc = run_digest(md, n, times, threads, updates);
    else
        rc = run_sign(prov, sig_name, n, times);
    if (rc != 0)
        return rc;

    /* md/sig stay alive for GO3 loops; freed by process exit. */
    printf("%ld\n", n);
    fflush(stdout);
    /* P0-4 second trigger: EOF (one-shot pipes) exits 0, preserving the
     * P0-1/2/3 oracle behavior exactly. "GO" refetches both algs in a
     * fresh libctx so both M1 queries re-fire after the harvester's
     * stage-2 attach, then stdin blocks until EOF (settle window). */
    {
        char line[16];

        if (fgets(line, sizeof line, stdin) == NULL)
            return 0;
        if (strcmp(line, "GO\n") != 0) {
            fprintf(stderr, "evp_driver: want GO2\n");
            return 1;
        }
    }
    {
        OSSL_LIB_CTX *ctx2 = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *p2;
        EVP_MD *md2;
        EVP_SIGNATURE *sig2;

        if (ctx2 == NULL)
            return 2;
        p2 = OSSL_PROVIDER_load(ctx2, prov);
        md2 = EVP_MD_fetch(ctx2, dig_name, propquery);
        sig2 = want_sig
            ? EVP_SIGNATURE_fetch(ctx2, sig_name, propquery)
            : NULL;
        if (p2 == NULL || md2 == NULL || (want_sig && sig2 == NULL)) {
            fprintf(stderr, "evp_driver: ctx2 refetch failed\n");
            return 2;
        }
        EVP_MD_free(md2);
        EVP_SIGNATURE_free(sig2);
        if (*dig2_name != '\0') {
            EVP_MD *md2b = EVP_MD_fetch(ctx2, dig2_name, propquery);

            if (md2b == NULL) {
                fprintf(stderr, "evp_driver: ctx2 refetch2 digest failed\n");
                return 2;
            }
            EVP_MD_free(md2b);
        }
        if (want_sig && *sig2_name != '\0') {
            EVP_SIGNATURE *sig2b =
                EVP_SIGNATURE_fetch(ctx2, sig2_name, propquery);

            if (sig2b == NULL) {
                fprintf(stderr, "evp_driver: ctx2 refetch2 sign failed\n");
                return 2;
            }
            EVP_SIGNATURE_free(sig2b);
        }
        query_all_rounds(ctx2, prov);
        /* ctx2/provider intentionally alive: addresses must stay stable. */
        fprintf(stderr, "REFETCH2=ok\n");
    }
    /* P0-6 third trigger: EOF exits (all frozen flows); "GO" re-runs
     * the measurement loop (post-attach firing) and prints LOOPDONE. */
    {
        char line[16];

        for (;;) {
            if (fgets(line, sizeof line, stdin) == NULL)
                return 0;
            if (strcmp(line, "GO\n") != 0) {
                fprintf(stderr, "evp_driver: want GO3\n");
                return 1;
            }
            if (storm > 0) {
                rc = run_storm((int)storm);
            } else {
                /* Driver-side wall for the measured loop (P0-8): the
                 * script's GO->LOOPDONE poll has 1s quantum, useless at
                 * ms-scale loops. Authoritative; script wall cross-checks. */
                unsigned long long wt0 = now_ns();

                if (strcmp(alg, "digest") == 0)
                    rc = run_digest(md, n, times, threads, updates);
                else
                    rc = run_sign(prov, sig_name, n, times);
                if (rc != 0)
                    return rc;
                fprintf(stderr, "LOOPDONE wall_ns=%llu\n", now_ns() - wt0);
                continue;
            }
            if (rc != 0)
                return rc;
        }
    }
}
