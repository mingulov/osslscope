/* SPDX-License-Identifier: GPL-3.0-or-later */
/* T09 decoy FIPS provider: a minimal test provider built as
 * `fips.so` and loaded under the name "fips" via OPENSSL_MODULES.
 * It advertises one working digest (DECOY-DIGEST) so dispatch
 * callbacks really execute. The C4 oracle: the observer reports
 * provider_class unknown (no pinned enrollment covers these bytes)
 * despite the "fips" load name and filename — class never derives
 * from filename authority. With an explicit local enrollment of
 * this build as third-party, the class resolves to that pin.
 *
 * Build: gcc -shared -fPIC -O1 -o /tmp/decoy-mods/fips.so
 *            decoy_fips_provider.c -lcrypto
 * Drive: decoy_fips_driver /tmp/decoy-mods
 */
#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

struct decoy_ctx {
    unsigned long long n;
};

static void *decoy_newctx(void *provctx, const OSSL_PARAM params[])
{
    struct decoy_ctx *c = malloc(sizeof *c);

    (void)provctx;
    (void)params;
    if (c != NULL)
        c->n = 0;
    return c;
}

static void decoy_freectx(void *ctx)
{
    free(ctx);
}

static int decoy_init(void *ctx, const OSSL_PARAM params[])
{
    (void)params;
    ((struct decoy_ctx *)ctx)->n = 0;
    return 1;
}

static int decoy_update(void *ctx, const unsigned char *in, size_t len)
{
    (void)in;
    ((struct decoy_ctx *)ctx)->n += (unsigned long long)len;
    return 1;
}

static int decoy_final(void *ctx, unsigned char *out, size_t *outl, size_t outsz)
{
    struct decoy_ctx *c = ctx;

    if (outsz < 8)
        return 0;
    memset(out, 0, 8);
    out[7] = (unsigned char)(c->n & 0xff);
    *outl = 8;
    return 1;
}

static const OSSL_PARAM *decoy_gettable(void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_DEFN(OSSL_DIGEST_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return known;
}

static int decoy_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);

    if (p != NULL && !OSSL_PARAM_set_uint(p, 8))
        return 0;
    return 1;
}

static const OSSL_DISPATCH decoy_digest[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))decoy_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))decoy_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))decoy_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))decoy_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))decoy_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))decoy_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))decoy_gettable },
    { 0, NULL }
};

static const OSSL_ALGORITHM decoy_digests[] = {
    { "DECOY-DIGEST", "provider=fips", decoy_digest, "T09 decoy FIPS digest" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *decoy_query(void *provctx, int op, int *no_store)
{
    (void)provctx;
    *no_store = 0;
    if (op == OSSL_OP_DIGEST)
        return decoy_digests;
    return NULL;
}

static const OSSL_PARAM *decoy_gettable_params(void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return known;
}

static int decoy_get_params_fn(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "decoy-fips"))
        return 0;
    return 1;
}

static const OSSL_DISPATCH decoy_provider[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))decoy_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))decoy_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))decoy_get_params_fn },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    *out = decoy_provider;
    *provctx = NULL;
    return 1;
}
