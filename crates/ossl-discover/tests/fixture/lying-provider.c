/* Lying provider (P1 exit 4 M4-fence fixture): a forged DISPATCH
 * table the harvester must fence (count-only), never attribute —
 * plus multi-impl entries it must EMIT (revised doctrine: a
 * same-name second table is legitimate multi-impl, dumper-proven
 * on the default provider — DH ×4 impls, 255 such keys — and
 * libcrypto resolves it first-wins, so every backed row is a
 * true, attributable claim). Three digest algs, all fetched with
 * provider=lying:
 *   LYING-SHA      — the SAME name twice in one array with DIFFERENT
 *                    dispatch tables: honest multi-impl, both tables
 *                    backed → all 14 rows EMIT (proves the fence no
 *                    longer eats legitimate multi-impl — the old
 *                    disagreement rule cost exit-2 parity 0.79).
 *   LYING-UNBACKED — newctx/freectx/init/update/final are garbage
 *                    constants (unmapped, deterministic): forged
 *                    DISPATCH → unbacked fence. gettable/get_params
 *                    are REAL: fetch calls them eagerly during method
 *                    construction (gdb-proven: evp_do_md_getparams),
 *                    while NULL mandatory fns fail fetch and garbage
 *                    elsewhere stays uninvoked (3.x and 4.x smoke).
 *                    The observer never dereferences these (M4); the
 *                    driver only fetches, never invokes (invoking a
 *                    garbage fn would crash by design).
 *   SHA256         — CONTROL: an impersonated well-known name with an
 *                    honest, consistent, backed table. P1 CANNOT prove
 *                    name-trust without a manifest (P3 owns it) and
 *                    must NOT fence it: emitted with truthful backing
 *                    (proves the fence doesn't over-fire).
 * Expected harvest: 23 rows (14 LYING-SHA + 7 control + 2 real
 * UNBACKED gettable/get_params) + fenced_rows=5 (garbage only),
 * PARTIAL with reason fenced-rows. No signature algs (one op
 * suffices). Cross-query table shifting is out of P1 scope (no
 * wild incidence; catching it needs per-query row tags).
 * NOTE: libcrypto tolerates the duplicate LYING-SHA entries (first-
 * wins store; fetch succeeds) — verified on 3.0/3.5/4.0 by smoke.
 * If a future libcrypto hard-fails dup names, this fixture fails
 * loudly at fetch (driver exit 2), never silently. */
#include <stdlib.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define LYING_DIGEST_ALG(id) \
    static void *id##_newctx(void *provctx) \
    { (void)provctx; return malloc(1); } \
    static void id##_freectx(void *ctx) { free(ctx); } \
    static int id##_init(void *ctx, const OSSL_PARAM params[]) \
    { (void)ctx; (void)params; return 1; } \
    static int id##_update(void *ctx, const void *in, size_t len) \
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
        { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, \
          (void (*)(void))id##_gettable }, \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))id##_get_params }, \
        { 0, NULL } \
    };

LYING_DIGEST_ALG(LYING_SHA_A)
LYING_DIGEST_ALG(LYING_SHA_B)
LYING_DIGEST_ALG(LYING_CTRL)
/* Only gettable/get_params are used (fetch calls them eagerly);
 * the rest are garbage below. Unused-func warnings suppressed at
 * build (-Wno-unused-function): this table is deliberately partial. */
LYING_DIGEST_ALG(LYING_UB_REAL)

/* Garbage impl constants (unmapped, deterministic across runs —
 * fenced rows emit nothing, so no golden instability anyway). */
#define LYING_GARBAGE(k) ((void (*)(void))(0xdeadbeef0000UL + (k) * 0x100UL))

static const OSSL_DISPATCH lying_unbacked_dispatch[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, LYING_GARBAGE(0) },
    { OSSL_FUNC_DIGEST_FREECTX, LYING_GARBAGE(1) },
    { OSSL_FUNC_DIGEST_INIT, LYING_GARBAGE(2) },
    { OSSL_FUNC_DIGEST_UPDATE, LYING_GARBAGE(3) },
    { OSSL_FUNC_DIGEST_FINAL, LYING_GARBAGE(4) },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,
      (void (*)(void))LYING_UB_REAL_gettable },
    { OSSL_FUNC_DIGEST_GET_PARAMS,
      (void (*)(void))LYING_UB_REAL_get_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM lying_digests[] = {
    { "LYING-SHA", "provider=lying", LYING_SHA_A_dispatch,
      "lying fixture A" },
    { "LYING-SHA", "provider=lying", LYING_SHA_B_dispatch,
      "lying fixture B (same name, other impl)" },
    { "LYING-UNBACKED", "provider=lying", lying_unbacked_dispatch,
      "lying fixture (forged pointers)" },
    { "SHA256", "provider=lying", LYING_CTRL_dispatch,
      "lying control (honest table)" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *lying_query(void *provctx, int operation_id,
                                         int *no_store)
{
    (void)provctx;
    *no_store = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return lying_digests;
    default:
        return NULL;
    }
}

static const OSSL_PARAM *lying_gettable_params(void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return known;
}

static int lying_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "LYING"))
        return 0;
    return 1;
}

static const OSSL_DISPATCH lying_provider[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))lying_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))lying_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))lying_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    *out = lying_provider;
    *provctx = NULL;
    return 1;
}
