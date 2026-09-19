/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Sentinel provider (P4 exit 2): hostile algorithm names + an
 * overlong digest array. The query fn returns a runtime-built
 * OSSL_ALGORITHM array: 4 sentinel-named algs (short, exact-128,
 * overlong-200, unterminated) + 516 filler algs = 520 entries:
 * slots 0..511 walk, the guard at slot 512 sees live entries
 * (TRUNC_ALGS must fire). All names carry
 * the CNRY7QN- prefix: the canary scanner asserts the prefix is
 * PRESENT in the raw ring dump (alias lanes really traversed the
 * string-read site) and ABSENT from every classified artifact.
 * All algs share one digest dispatch table (fetch-safe bodies). */
#include <stdlib.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define N_ALG_SHORT "CNRY7QN-ALG-SHORT-25"
#define N_ALG_128_PFX "CNRY7QN-ALG-128-26-"
#define N_ALG_LONG_PFX "CNRY7QN-ALG-LONG-27-"
#define N_ALG_UNTERM_PFX "CNRY7QN-ALG-UNTERM-28-"
#define N_FILLER_PFX "CNRY7QN-FILLER-"
#define N_FILLERS 516

static void *sn_newctx(void *provctx)
{
    (void)provctx;
    return malloc(1);
}

static void sn_freectx(void *ctx)
{
    free(ctx);
}

static int sn_init(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static int sn_update(void *ctx, const unsigned char *in, size_t len)
{
    (void)ctx;
    (void)in;
    (void)len;
    return 1;
}

static int sn_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)ctx;
    (void)out;
    (void)outsz;
    *outl = 0;
    return 1;
}

static const OSSL_PARAM *sn_gettable(void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return known;
}

static int sn_get_params(OSSL_PARAM params[])
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

static const OSSL_DISPATCH sn_dispatch[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))sn_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))sn_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))sn_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))sn_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))sn_final },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))sn_gettable },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))sn_get_params },
    { 0, NULL }
};

/* Runtime-built array (init-time): 4 sentinel + N_FILLER filler. */
static OSSL_ALGORITHM *sn_digests;
static char sn_name128[128];   /* 127 chars + NUL: exact BPF window */
static char sn_name200[201];   /* 200 chars + NUL: overlong window */
static char sn_name_unterm[256]; /* prefix + 'U' fill, NO NUL anywhere */
static char sn_fillers[N_FILLERS][32];

static void build_array(void)
{
    int i;

    if (sn_digests != NULL)
        return;
    memset(sn_name128, 'A', sizeof sn_name128 - 1);
    sn_name128[sizeof sn_name128 - 1] = '\0';
    memcpy(sn_name128, N_ALG_128_PFX, sizeof N_ALG_128_PFX - 1);
    memset(sn_name200, 'B', sizeof sn_name200 - 1);
    sn_name200[sizeof sn_name200 - 1] = '\0';
    memcpy(sn_name200, N_ALG_LONG_PFX, sizeof N_ALG_LONG_PFX - 1);
    memset(sn_name_unterm, 'U', sizeof sn_name_unterm);
    memcpy(sn_name_unterm, N_ALG_UNTERM_PFX, sizeof N_ALG_UNTERM_PFX - 1);
    for (i = 0; i < N_FILLERS; i++)
        snprintf(sn_fillers[i], sizeof sn_fillers[i], "%s%03d",
                 N_FILLER_PFX, i);
    sn_digests = calloc((size_t)(4 + N_FILLERS + 1), sizeof *sn_digests);
    if (sn_digests == NULL)
        return;
    sn_digests[0].algorithm_names = N_ALG_SHORT;
    sn_digests[1].algorithm_names = sn_name128;
    sn_digests[2].algorithm_names = sn_name200;
    sn_digests[3].algorithm_names = sn_name_unterm;
    for (i = 0; i < N_FILLERS; i++)
        sn_digests[4 + i].algorithm_names = sn_fillers[i];
    for (i = 0; i < 4 + N_FILLERS; i++) {
        sn_digests[i].property_definition = "provider=sentinel";
        sn_digests[i].implementation = sn_dispatch;
        sn_digests[i].algorithm_description = "sentinel fixture";
    }
}

static const OSSL_ALGORITHM *sn_query(void *provctx, int operation_id,
                                      int *no_store)
{
    (void)provctx;
    (void)no_store;
    if (operation_id == OSSL_OP_DIGEST)
        return sn_digests;
    return NULL;
}

static const OSSL_DISPATCH sn_provider[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sn_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    build_array();
    if (sn_digests == NULL)
        return 0;
    *out = sn_provider;
    *provctx = NULL;
    return 1;
}
