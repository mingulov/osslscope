/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPIKE test provider: 2 DIGEST + 2 SIGNATURE algs, 26 dispatch entries.
 * Every callback appends "ALG:funcid:FUNC" to $SPIKE_COUNTER_FILE (default
 * /tmp/spike-counters.log) and returns success. -DSPIKE_NO_COUNT compiles
 * the counting out (P0-8 overhead runs). P0-2 fixture; ground
 * truth N = 26 dispatch entries (14 digest + 12 sig). */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static void spike_count(const char *alg, int funcid, const char *func)
{
#ifdef SPIKE_NO_COUNT
    (void)alg; (void)funcid; (void)func;
    return;
#else
    const char *path = getenv("SPIKE_COUNTER_FILE");
    FILE *f;

    if (path == NULL || *path == '\0')
        path = "/tmp/spike-counters.log";
    f = fopen(path, "a");
    if (f == NULL)
        return;
    fprintf(f, "%s:%d:%s\n", alg, funcid, func);
    fclose(f);
#endif
}

/* P0-8: emulated provider work (~1-2us) so the overhead baseline is a
 * realistic us-scale op instead of a ~0.1us no-op (a no-op base would
 * make the min(4us, base) gate vacuous). Counts/oracle unaffected. */
static void spike_work(void)
{
    volatile unsigned i;

    for (i = 0; i < 3000; i++)
        ;
}

/* Shared digest metadata readers (ONE address for every digest alg —
 * real providers share these across SHA2/SHA3 families (P1-exit-2
 * alias precedent); per-alg-private copies would leave the fetch
 * walk's sibling-alg calls unprobed and break P2 churn conservation.
 * Oracle labels shared calls SPIKE-SHA (per-alg attribution of a
 * shared address is impossible — the alias audit says so). */
static const OSSL_PARAM *spike_digest_gettable(void *provctx)
{
    (void)provctx;
    spike_count("SPIKE-SHA", OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
        "gettable_params");
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known;
}

static int spike_digest_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    spike_count("SPIKE-SHA", OSSL_FUNC_DIGEST_GET_PARAMS, "get_params");
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 64))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 32))
        return 0;
    return 1;
}

#define SPIKE_DIGEST_ALG(id, disp) \
    static void *id##_newctx(void *provctx) \
    { (void)provctx; spike_count(disp, OSSL_FUNC_DIGEST_NEWCTX, "newctx"); return malloc(1); } \
    static void id##_freectx(void *ctx) \
    { spike_count(disp, OSSL_FUNC_DIGEST_FREECTX, "freectx"); free(ctx); } \
    static int id##_init(void *ctx, const OSSL_PARAM params[]) \
    { (void)ctx; (void)params; spike_count(disp, OSSL_FUNC_DIGEST_INIT, "init"); return 1; } \
    static int id##_update(void *ctx, const unsigned char *in, size_t len) \
    { (void)ctx; (void)in; (void)len; spike_count(disp, OSSL_FUNC_DIGEST_UPDATE, "update"); spike_work(); return 1; } \
    static int id##_final(void *ctx, unsigned char *out, size_t *outl, \
                          size_t outsz) \
    { (void)ctx; (void)out; (void)outsz; spike_count(disp, OSSL_FUNC_DIGEST_FINAL, "final"); \
      *outl = 0; return 1; } \
    static const OSSL_DISPATCH id##_dispatch[] = { \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))id##_newctx }, \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))id##_freectx }, \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))id##_init }, \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))id##_update }, \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))id##_final }, \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))spike_digest_gettable }, \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))spike_digest_get_params }, \
        { 0, NULL } \
    };

#define SPIKE_SIG_ALG(id, disp) \
    static void *id##_newctx(void *provctx, const char *propq) \
    { (void)provctx; (void)propq; spike_count(disp, OSSL_FUNC_SIGNATURE_NEWCTX, "newctx"); \
      return malloc(1); } \
    static void id##_freectx(void *ctx) \
    { spike_count(disp, OSSL_FUNC_SIGNATURE_FREECTX, "freectx"); free(ctx); } \
    static int id##_sign_init(void *ctx, void *provkey, \
                             const OSSL_PARAM params[]) \
    { (void)ctx; (void)provkey; (void)params; \
      spike_count(disp, OSSL_FUNC_SIGNATURE_SIGN_INIT, "sign_init"); return 1; } \
    static int id##_sign(void *ctx, unsigned char *sig, size_t *siglen, \
                        size_t sigsize, const unsigned char *tbs, \
                        size_t tbslen) \
    { (void)ctx; (void)tbs; (void)tbslen; spike_count(disp, OSSL_FUNC_SIGNATURE_SIGN, "sign"); \
      if (sig == NULL || sigsize >= 32) { *siglen = 32; return 1; } \
      return 0; } \
    static int id##_verify_init(void *ctx, void *provkey, \
                               const OSSL_PARAM params[]) \
    { (void)ctx; (void)provkey; (void)params; \
      spike_count(disp, OSSL_FUNC_SIGNATURE_VERIFY_INIT, "verify_init"); return 1; } \
    static int id##_verify(void *ctx, const unsigned char *sig, \
                          size_t siglen, const unsigned char *tbs, \
                          size_t tbslen) \
    { (void)ctx; (void)sig; (void)siglen; (void)tbs; (void)tbslen; \
      spike_count(disp, OSSL_FUNC_SIGNATURE_VERIFY, "verify"); return 1; } \
    static const OSSL_DISPATCH id##_dispatch[] = { \
        { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))id##_newctx }, \
        { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))id##_freectx }, \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))id##_sign_init }, \
        { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))id##_sign }, \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))id##_verify_init }, \
        { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))id##_verify }, \
        { 0, NULL } \
    };

SPIKE_DIGEST_ALG(SPIKE_SHA, "SPIKE-SHA")
SPIKE_DIGEST_ALG(SPIKE_SHA2, "SPIKE-SHA2")
SPIKE_SIG_ALG(SPIKE_SIG, "SPIKE-SIG")
SPIKE_SIG_ALG(SPIKE_SIG2, "SPIKE-SIG2")

static const OSSL_ALGORITHM spike_digests[] = {
    { "SPIKE-SHA", "provider=spike", SPIKE_SHA_dispatch,
      "SPIKE digest fixture" },
    { "SPIKE-SHA2", "provider=spike", SPIKE_SHA2_dispatch,
      "SPIKE digest fixture" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM spike_sigs[] = {
    { "SPIKE-SIG", "provider=spike", SPIKE_SIG_dispatch,
      "SPIKE signature fixture" },
    { "SPIKE-SIG2", "provider=spike", SPIKE_SIG2_dispatch,
      "SPIKE signature fixture" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *spike_query(void *provctx, int operation_id,
                                         int *no_store)
{
    (void)provctx;
    *no_store = getenv("SPIKE_NO_STORE") != NULL ? 1 : 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return spike_digests;
    case OSSL_OP_SIGNATURE:
        return spike_sigs;
    default:
        return NULL;
    }
}

static const OSSL_PARAM *spike_gettable_params(void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return known;
}

static int spike_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "SPIKE"))
        return 0;
    return 1;
}

/* P0-9: lifecycle marks (init/teardown) prove real load/unload cycles:
 * same-file remaps reuse the base within a process (loader cache), so
 * base-variation can't prove churn — teardown count can. */
static void spike_mark(const char *s)
{
    const char *path;
    FILE *f;

    if (getenv("SPIKE_LIFECYCLE") == NULL)
        return;
    path = getenv("SPIKE_COUNTER_FILE");
    if (path == NULL || *path == '\0')
        path = "/tmp/spike-counters.log";
    f = fopen(path, "a");
    if (f == NULL)
        return;
    fprintf(f, "%s\n", s);
    fclose(f);
}

static void spike_teardown(void *provctx)
{
    (void)provctx;
    spike_mark("TEARDOWN spike");
}

static const OSSL_DISPATCH spike_provider[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))spike_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))spike_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))spike_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))spike_get_params },
    { 0, NULL } /* no OSSL_DISPATCH_END in 3.0/3.5/4.0 headers (verified) */
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    *out = spike_provider;
    *provctx = NULL;
    spike_mark("INIT spike");
    return 1;
}
