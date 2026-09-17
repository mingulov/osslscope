/* lying_driver.c — fetch-only driver for the P1 exit-4 lying
 * provider. Fetches LYING-SHA + LYING-UNBACKED + SHA256 (provider=
 * lying) but NEVER invokes any digest op: LYING-UNBACKED's dispatch
 * points at NULL/garbage by design (invoking would crash — the
 * observer must fence the pointers, never follow them).
 * Usage: lying_driver (GO1: fetch all three, GO2: refetch LYING-SHA
 * in a fresh libctx, EOF: exit 0). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static int want_go(const char *want)
{
    char line[16];

    if (fgets(line, sizeof line, stdin) == NULL)
        return -1;
    if (strcmp(line, "GO\n") != 0) {
        fprintf(stderr, "lying_driver: want %s\n", want);
        return 1;
    }
    return 0;
}

static int fetch_all(OSSL_LIB_CTX *ctx, const char *tag)
{
    static const char *algs[] = {
        "LYING-SHA", "LYING-UNBACKED", "SHA256", NULL
    };
    int i;

    for (i = 0; algs[i] != NULL; i++) {
        EVP_MD *md = EVP_MD_fetch(ctx, algs[i], "provider=lying");

        if (md == NULL) {
            fprintf(stderr, "lying_driver: %s fetch %s failed\n", tag, algs[i]);
            return 1;
        }
        EVP_MD_free(md);
    }
    return 0;
}

int main(void)
{
    OSSL_LIB_CTX *ctx2;
    OSSL_PROVIDER *p2;
    int rc;

    fprintf(stderr, "PID=%d\n", (int)getpid());
    rc = want_go("GO1");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    if (OSSL_PROVIDER_load(NULL, "lying") == NULL) {
        fprintf(stderr, "lying_driver: lying load failed\n");
        return 2;
    }
    if (fetch_all(NULL, "GO1") != 0)
        return 2;
    fprintf(stderr, "LYINGDONE\n");
    rc = want_go("GO2");
    if (rc < 0)
        return 0;
    if (rc != 0)
        return 1;
    /* Fresh-libctx refetch (re-query deterministically post-attach;
     * same addrs — deduped, proving observation stability). */
    ctx2 = OSSL_LIB_CTX_new();
    if (ctx2 == NULL)
        return 2;
    p2 = OSSL_PROVIDER_load(ctx2, "lying");
    if (p2 == NULL) {
        fprintf(stderr, "lying_driver: GO2 load failed\n");
        OSSL_LIB_CTX_free(ctx2);
        return 2;
    }
    if (fetch_all(ctx2, "GO2") != 0) {
        OSSL_LIB_CTX_free(ctx2);
        return 2;
    }
    OSSL_LIB_CTX_free(ctx2);
    fprintf(stderr, "REFETCH2=ok\n");
    if (want_go("EOF") < 0)
        return 0;
    return 0;
}
