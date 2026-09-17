/* Deliberate-alias provider (P1 exit-2 alias-audit fixture): 3 DIGEST
 * algs, 21 dispatch entries. ALIAS-A + ALIAS-B share ONE dispatch table
 * (identical function addresses); ALIAS-OWN has its own table.
 * Expected harvest: 21 rows; alias-audit must report exactly 7 groups
 * of 2 members (the shared table) and no singleton groups. */
#include <stdlib.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define ALIAS_DIGEST_ALG(id) \
    static void *id##_newctx(void *provctx) \
    { (void)provctx; return malloc(1); } \
    static void id##_freectx(void *ctx) { free(ctx); } \
    static int id##_init(void *ctx, const OSSL_PARAM params[]) \
    { (void)ctx; (void)params; return 1; } \
    static int id##_update(void *ctx, const unsigned char *in, size_t len) \
    { (void)ctx; (void)in; (void)len; return 1; } \
    static int id##_final(void *ctx, unsigned char *out, size_t *outl, \
                          size_t outsz) \
    { (void)ctx; (void)out; (void)outsz; *outl = 0; return 1; } \
    static const OSSL_PARAM *id##_gettable(void *provctx) \
    { (void)provctx; \
      static const OSSL_PARAM known[] = { \
          OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL), \
          OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL), \
          OSSL_PARAM_END \
      }; \
      return known; } \
    static int id##_get_params(OSSL_PARAM params[]) \
    { OSSL_PARAM *p; \
      p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE); \
      if (p != NULL && !OSSL_PARAM_set_size_t(p, 64)) return 0; \
      p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE); \
      if (p != NULL && !OSSL_PARAM_set_size_t(p, 32)) return 0; \
      return 1; } \
    static const OSSL_DISPATCH id##_dispatch[] = { \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))id##_newctx }, \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))id##_freectx }, \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))id##_init }, \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))id##_update }, \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))id##_final }, \
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))id##_gettable }, \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))id##_get_params }, \
        { 0, NULL } \
    };

ALIAS_DIGEST_ALG(SHARED)
ALIAS_DIGEST_ALG(OWN)

static const OSSL_ALGORITHM alias_digests[] = {
    { "ALIAS-A", "provider=alias", SHARED_dispatch, "alias fixture" },
    { "ALIAS-B", "provider=alias", SHARED_dispatch, "alias fixture" },
    { "ALIAS-OWN", "provider=alias", OWN_dispatch, "alias fixture" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *alias_query(void *provctx, int operation_id,
                                         int *no_store)
{
    (void)provctx;
    (void)no_store;
    if (operation_id == OSSL_OP_DIGEST)
        return alias_digests;
    return NULL;
}

static const OSSL_DISPATCH alias_provider[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))alias_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    *out = alias_provider;
    *provctx = NULL;
    return 1;
}
