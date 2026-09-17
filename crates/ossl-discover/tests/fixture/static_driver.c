/* static_driver.c — statically-linked provider target (P1 exit-2
 * static-provider fixture). Links min-provider.c INTO the executable
 * (no .so); the provider registers via OSSL_PROVIDER_add_builtin.
 * Build WITHOUT -rdynamic so OSSL_provider_init is absent from .dynsym:
 * inspect must emit PARTIAL + uninstrumented_ops>0, never bare "none"
 * (and full rows when symtab is present — the ladder is dynsym>symtab).
 * GO protocol mirrors evp_driver GO1/GO2 (fetch both algs, refetch in a
 * fresh libctx, block till EOF).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_dispatch.h>

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx);

/* Inventory trigger (mirrors evp_driver's): re-query every op so the
 * one-alg-per-hit walk covers the full arrays. Only the instrumented
 * builtin is queried (default/legacy would be invisible work). */
static void query_all_rounds(OSSL_PROVIDER *p)
{
    const char *er = getenv("SPIKE_QUERY_ROUNDS");
    int rounds = er != NULL ? atoi(er) : 256;
    int r, op;

    if (getenv("SPIKE_QUERY_ALL") == NULL)
        return;
    if (rounds < 1)
        rounds = 1;
    if (rounds > 1024)
        rounds = 1024;
    for (op = 1; op <= OSSL_OP__HIGHEST; op++) {
        for (r = 0; r < rounds; r++) {
            const OSSL_ALGORITHM *a;
            int no = 0;

            a = OSSL_PROVIDER_query_operation(p, op, &no);
            OSSL_PROVIDER_unquery_operation(p, op, a);
        }
    }
    fprintf(stderr, "QUERYALL=ok rounds=%d\n", rounds);
}

static int wait_go(const char *want)
{
    char line[16];

    if (fgets(line, sizeof line, stdin) == NULL) {
        fprintf(stderr, "static_driver: EOF want %s\n", want);
        return 0;
    }
    if (strcmp(line, "GO\n") != 0) {
        fprintf(stderr, "static_driver: want %s\n", want);
        return 0;
    }
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx2;
    OSSL_PROVIDER *p0, *p2;
    EVP_MD *md, *md2;
    EVP_SIGNATURE *sig, *sig2;

    fprintf(stderr, "PID=%d\n", (int)getpid());
    if (!wait_go("GO1"))
        return 1;
    if (!OSSL_PROVIDER_add_builtin(NULL, "spikestatic", OSSL_provider_init)
        || (p0 = OSSL_PROVIDER_load(NULL, "spikestatic")) == NULL) {
        fprintf(stderr, "static_driver: builtin load failed\n");
        return 2;
    }
    /* Unqualified fetch: the builtin is the only SPIKE-SHA source
     * (default lacks it; modules never auto-load). The provider-name
     * assert below proves the builtin served the fetch. */
    md = EVP_MD_fetch(NULL, "SPIKE-SHA", NULL);
    sig = EVP_SIGNATURE_fetch(NULL, "SPIKE-SIG", NULL);
    if (md == NULL || sig == NULL) {
        fprintf(stderr, "static_driver: fetch failed\n");
        return 2;
    }
    if (strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)),
               "spikestatic") != 0
        || strcmp(OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(sig)),
                  "spikestatic") != 0) {
        fprintf(stderr, "static_driver: fetch not served by builtin\n");
        return 2;
    }
    query_all_rounds(p0);
    if (!wait_go("GO2"))
        return 1;
    ctx2 = OSSL_LIB_CTX_new();
    if (ctx2 == NULL)
        return 2;
    if (!OSSL_PROVIDER_add_builtin(ctx2, "spikestatic", OSSL_provider_init)
        || (p2 = OSSL_PROVIDER_load(ctx2, "spikestatic")) == NULL) {
        fprintf(stderr, "static_driver: ctx2 load failed\n");
        return 2;
    }
    md2 = EVP_MD_fetch(ctx2, "SPIKE-SHA", NULL);
    sig2 = EVP_SIGNATURE_fetch(ctx2, "SPIKE-SIG", NULL);
    if (md2 == NULL || sig2 == NULL) {
        fprintf(stderr, "static_driver: ctx2 refetch failed\n");
        return 2;
    }
    EVP_MD_free(md2);
    EVP_SIGNATURE_free(sig2);
    query_all_rounds(p2);
    fprintf(stderr, "REFETCH2=ok\n");
    for (;;) {
        char line[16];

        if (fgets(line, sizeof line, stdin) == NULL)
            return 0;
    }
}
