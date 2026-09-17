/* Canary provider (P1 exit 1): 1 DIGEST + 1 SIGNATURE with canary
 * names that must NEVER appear in inspect output (registry-class at
 * emission maps them to "other"). 13 dispatch entries total (7+6).
 * Digest: "canary-DOOM-7QZ". Signature: "SPIKE-SECRET-9QZ".
 * Dispatch sets mirror min-provider (fetch requires them complete). */
#include <stdlib.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static void *c_newctx(void *provctx)
{
    (void)provctx;
    return malloc(1);
}

static void c_freectx(void *ctx)
{
    free(ctx);
}

static int c_init(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static int c_update(void *ctx, const unsigned char *in, size_t len)
{
    (void)ctx;
    (void)in;
    (void)len;
    return 1;
}

static int c_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)ctx;
    (void)out;
    (void)outsz;
    *outl = 0;
    return 1;
}

static const OSSL_PARAM c_gettable[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *c_gettable_params(void *provctx)
{
    (void)provctx;
    return c_gettable;
}

static int c_get_params(OSSL_PARAM params[])
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

static void *c_sig_newctx(void *provctx, const char *propq)
{
    (void)provctx;
    (void)propq;
    return malloc(1);
}

static void c_sig_freectx(void *ctx)
{
    free(ctx);
}

static int c_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)provkey;
    (void)params;
    return 1;
}

static int c_sign(void *ctx, unsigned char *sig, size_t *siglen,
                  size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    (void)ctx;
    (void)sig;
    (void)sigsize;
    (void)tbs;
    (void)tbslen;
    *siglen = 0;
    return 1;
}

static int c_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)provkey;
    (void)params;
    return 1;
}

static int c_verify(void *ctx, const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen)
{
    (void)ctx;
    (void)sig;
    (void)siglen;
    (void)tbs;
    (void)tbslen;
    return 1;
}

static const OSSL_DISPATCH canary_digest_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))c_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))c_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))c_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))c_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))c_final },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))c_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))c_get_params },
    { 0, NULL }
};

static const OSSL_DISPATCH canary_sig_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))c_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))c_sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))c_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))c_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))c_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))c_verify },
    { 0, NULL }
};

static const OSSL_ALGORITHM canary_digests[] = {
    { "canary-DOOM-7QZ", "provider=canary", canary_digest_fns,
      "canary digest" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM canary_sigs[] = {
    { "SPIKE-SECRET-9QZ", "provider=canary", canary_sig_fns,
      "canary signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *canary_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    (void)provctx;
    (void)no_cache;
    if (operation_id == OSSL_OP_DIGEST)
        return canary_digests;
    if (operation_id == OSSL_OP_SIGNATURE)
        return canary_sigs;
    return NULL;
}

static const OSSL_DISPATCH canary_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))canary_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *out = canary_dispatch;
    *provctx = NULL;
    return 1;
}
