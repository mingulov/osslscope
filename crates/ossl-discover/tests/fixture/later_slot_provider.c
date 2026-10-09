/* SPDX-License-Identifier: GPL-3.0-or-later */
/* T03 later-slot fixture provider: 4 DIGEST algs, static arrays,
 * no_store=0. Slots 0-2 are registered filler names; slot 3 is the
 * unregistered oracle target "T03-LATE" (kernel class `other`).
 * Every query appends "QUERY op=<id> no_store=<n>" to
 * $T03_ORACLE_FILE (default /tmp/t03-oracle.log) so the live lane
 * can prove the query count is bounded (one ordinary query, not
 * hundreds of trigger rounds). Digest callbacks are inert stubs:
 * this fixture proves table coverage, not execution counts. */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

static void *t03_newctx(void *provctx)
{
    (void)provctx;
    return malloc(1);
}

static void t03_freectx(void *ctx)
{
    free(ctx);
}

static int t03_init(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

static int t03_update(void *ctx, const unsigned char *in, size_t len)
{
    (void)ctx;
    (void)in;
    (void)len;
    return 1;
}

static int t03_final(void *ctx, unsigned char *out, size_t *outl,
                     size_t outsz)
{
    (void)ctx;
    (void)out;
    (void)outsz;
    *outl = 0;
    return 1;
}

/* One shared dispatch (funcids 1,2,3,4,6): every alg exposes
 * OSSL_FUNC_DIGEST_UPDATE (3), so the live test pins slot 3 via
 * (op=1, class=other, funcid=3). */
static const OSSL_DISPATCH t03_digest_dispatch[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))t03_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))t03_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))t03_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))t03_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))t03_freectx },
    { 0, NULL }
};

static const OSSL_ALGORITHM t03_digests[] = {
    { "SHA2-256", "provider=t03later", t03_digest_dispatch,
      "T03 filler slot 0" },
    { "SHA2-384", "provider=t03later", t03_digest_dispatch,
      "T03 filler slot 1" },
    { "SHA2-512", "provider=t03later", t03_digest_dispatch,
      "T03 filler slot 2" },
    { "T03-LATE", "provider=t03later", t03_digest_dispatch,
      "T03 oracle target slot 3" },
    { NULL, NULL, NULL, NULL }
};

static void t03_oracle(int operation_id, int no_store)
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

static const OSSL_ALGORITHM *t03_query(void *provctx, int operation_id,
                                       int *no_store)
{
    (void)provctx;
    *no_store = 0;
    t03_oracle(operation_id, 0);
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return t03_digests;
    default:
        return NULL;
    }
}

static void t03_teardown(void *provctx)
{
    (void)provctx;
}

static const OSSL_DISPATCH t03_provider[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))t03_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))t03_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    (void)handle;
    (void)in;
    *out = t03_provider;
    *provctx = NULL;
    return 1;
}
