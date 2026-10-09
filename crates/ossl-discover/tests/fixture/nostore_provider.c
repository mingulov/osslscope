/* SPDX-License-Identifier: GPL-3.0-or-later */
/* T03 no_store fixture provider: 3 DIGEST algs whose query always
 * sets *no_store=1 (uncacheable tables). The harvest walker must
 * sample slot 0 once, flag TRUNC_NO_STORE, and report PARTIAL —
 * never silently COMPLETE. Oracle ledger shares the
 * $T03_ORACLE_FILE "QUERY op=<id> no_store=<n>" format with
 * later_slot_provider.c. */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

static void *t03ns_newctx(void *provctx)
{
    (void)provctx;
    return malloc(1);
}

static void t03ns_freectx(void *ctx)
{
    free(ctx);
}

static int t03ns_init(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static int t03ns_update(void *ctx, const unsigned char *in, size_t len)
{
    (void)ctx;
    (void)in;
    (void)len;
    return 1;
}

static int t03ns_final(void *ctx, unsigned char *out, size_t *outl,
                       size_t outsz)
{
    (void)ctx;
    (void)out;
    (void)outsz;
    *outl = 0;
    return 1;
}

static const OSSL_DISPATCH t03ns_digest_dispatch[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))t03ns_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))t03ns_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))t03ns_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))t03ns_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))t03ns_freectx },
    { 0, NULL }
};

static const OSSL_ALGORITHM t03ns_digests[] = {
    { "SHA2-256", "provider=t03nostore", t03ns_digest_dispatch,
      "T03 no_store slot 0" },
    { "SHA2-384", "provider=t03nostore", t03ns_digest_dispatch,
      "T03 no_store slot 1" },
    { "T03-NS-LATE", "provider=t03nostore", t03ns_digest_dispatch,
      "T03 no_store slot 2" },
    { NULL, NULL, NULL, NULL }
};

static void t03ns_oracle(int operation_id, int no_store)
{
    const char *path = getenv("T03_ORACLE_FILE");
    FILE *f;

    if (path == NULL || *path == '\0')
        path = "/tmp/t03-oracle.log";
    f = fopen(path, "a");
    if (f == NULL)
        return;
    fprintf(f, "QUERY op=%d no_store=%d\n", operation_id, no_store);
    fclose(f);
}

static const OSSL_ALGORITHM *t03ns_query(void *provctx, int operation_id,
                                         int *no_store)
{
    (void)provctx;
    *no_store = 1;
    t03ns_oracle(operation_id, 1);
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return t03ns_digests;
    default:
        return NULL;
    }
}

static void t03ns_teardown(void *provctx)
{
    (void)provctx;
}

static const OSSL_DISPATCH t03ns_provider[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))t03ns_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))t03ns_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    *out = t03ns_provider;
    *provctx = NULL;
    return 1;
}
