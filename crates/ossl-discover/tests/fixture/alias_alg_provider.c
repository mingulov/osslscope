/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Alias-alg provider (T02 live privacy gate): every decoded
 * algorithm_names pointer aliases a DISTINCT secret sentinel.
 * The query fn returns a runtime-built OSSL_ALGORITHM array with
 * two sentinel-named digest algs (short + overlong-200) sharing one
 * fetch-safe dispatch table:
 *   slot 0: T02ALIAS-ALG-SHORT-01  (readable, unregistered)
 *   slot 1: T02ALG-LONG buffer     (200 chars + NUL: overlong window)
 * Live-gate procedure (needs the approved lane + T05 harness; NOT
 * run in T02): harvest this provider, then assert (a) zero bytes of
 * either sentinel in inspect/report/check/CBOM/stdout/stderr, live
 * rings, and every inventoried map, and (b) the positive control:
 * classified `other` rows for slot 0 plus an overlong verdict for
 * slot 1 (unknown/overlong evidence proves the alias lanes really
 * traversed the kernel string-read site). */
#include <stdlib.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define N_ALG_SHORT "T02ALIAS-ALG-SHORT-01"
#define N_ALG_LONG_PFX "T02ALIAS-ALG-LONG-02-"

static void *al_newctx(void *provctx)
{
    (void)provctx;
    return malloc(1);
}

static void al_freectx(void *ctx)
{
    free(ctx);
}

static int al_init(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static int al_update(void *ctx, const unsigned char *in, size_t len)
{
    (void)ctx;
    (void)in;
    (void)len;
    return 1;
}

static int al_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)ctx;
    (void)out;
    (void)outsz;
    *outl = 0;
    return 1;
}

static const OSSL_PARAM *al_gettable(void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return known;
}

static int al_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 64))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 32))
        return 0;
    return 1;
}

static const OSSL_DISPATCH al_dispatch[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))al_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))al_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))al_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))al_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))al_final },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))al_gettable },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))al_get_params },
    { 0, NULL }
};

/* Distinct secret sentinel buffers; the array below aliases them. */
static char al_name_short[] = N_ALG_SHORT;
static char al_name_long[201]; /* 200 chars + NUL */
static OSSL_ALGORITHM al_digests[3];

static void build_array(void)
{
    static int built;

    if (built)
        return;
    built = 1;
    memset(al_name_long, 'B', sizeof al_name_long - 1);
    al_name_long[sizeof al_name_long - 1] = '\0';
    memcpy(al_name_long, N_ALG_LONG_PFX, sizeof N_ALG_LONG_PFX - 1);
    al_digests[0].algorithm_names = al_name_short;
    al_digests[0].property_definition = "provider=alias-alg";
    al_digests[0].implementation = al_dispatch;
    al_digests[0].algorithm_description = "alias fixture short";
    al_digests[1].algorithm_names = al_name_long;
    al_digests[1].property_definition = "provider=alias-alg";
    al_digests[1].implementation = al_dispatch;
    al_digests[1].algorithm_description = "alias fixture overlong";
    memset(&al_digests[2], 0, sizeof al_digests[2]);
}

static const OSSL_ALGORITHM *al_query(void *provctx, int operation_id,
                                      int *no_store)
{
    (void)provctx;
    (void)no_store;
    if (operation_id == OSSL_OP_DIGEST)
        return al_digests;
    return NULL;
}

static const OSSL_DISPATCH al_provider[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))al_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    build_array();
    *out = al_provider;
    *provctx = NULL;
    return 1;
}
