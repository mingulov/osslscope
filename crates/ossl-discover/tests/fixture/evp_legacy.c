/* P1 exit-3 TP driver: spike EVP fetch (dispatch trigger) plus direct
 * low-level DES calls (legacy tripwire ground truth).
 * Usage: evp_legacy -n N -legacy K (GO1: work, GO2: retrigger, EOF: exit 0).
 * stdout: exactly "%ld\n" with N. stderr: PID=/provider/N=/CALLBACKS=/
 * LEGACYDONE markers. Env: SPIKE_PROV/SPIKE_DIGEST select provider + alg.
 * The DES calls go through this binary's PLT: caller-attributed
 * low-level probes must observe exactly the K(+1) cipher/block calls. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static unsigned char input[1024];

static int run_digest(EVP_MD *md, long n)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64];
    unsigned int outl = 0;
    long i;

    if (ctx == NULL)
        return 1;
    for (i = 0; i < n; i++) {
        if (!EVP_DigestInit_ex2(ctx, md, NULL)
            || !EVP_DigestUpdate(ctx, input, sizeof input)
            || !EVP_DigestFinal_ex(ctx, out, &outl)) {
            fprintf(stderr, "legacy: digest iter %ld failed\n", i);
            EVP_MD_CTX_free(ctx);
            return 1;
        }
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

static int run_des(long k)
{
    DES_cblock key = { 1, 2, 3, 4, 5, 6, 7, 8 };
    DES_cblock in = { 8, 7, 6, 5, 4, 3, 2, 1 };
    DES_cblock out;
    DES_key_schedule ks;
    long i;

    DES_set_key_unchecked(&key, &ks);
    for (i = 0; i < k; i++)
        DES_ecb_encrypt(&in, &out, &ks, DES_ENCRYPT);
    if (out[0] == in[0] && out[7] == in[7] && k > 0) {
        fprintf(stderr, "legacy: DES identity (no-op call?)\n");
        return 1;
    }
    return 0;
}

static int want_go(const char *want)
{
    char line[16];

    if (fgets(line, sizeof line, stdin) == NULL)
        return -1;
    if (strcmp(line, "GO\n") != 0) {
        fprintf(stderr, "evp_legacy: want %s\n", want);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    long n = -1, k = -1;
    const char *prov, *dig_name;
    char propquery[128];
    EVP_MD *md;
    int i, rc;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atol(argv[++i]);
        } else if (strcmp(argv[i], "-legacy") == 0 && i + 1 < argc) {
            k = atol(argv[++i]);
        } else {
            fprintf(stderr, "usage: evp_legacy -n N -legacy K\n");
            return 1;
        }
    }
    if (n < 0 || k < 0) {
        fprintf(stderr, "usage: evp_legacy -n N -legacy K\n");
        return 1;
    }
    fprintf(stderr, "PID=%d\n", (int)getpid());
    if (want_go("GO1") != 0)
        return 1;

    prov = getenv("SPIKE_PROV");
    if (prov == NULL || *prov == '\0')
        prov = "spike";
    dig_name = getenv("SPIKE_DIGEST");
    if (dig_name == NULL || *dig_name == '\0')
        dig_name = "SPIKE-SHA";
    snprintf(propquery, sizeof propquery, "provider=%s", prov);
    if (!OSSL_PROVIDER_available(NULL, prov)
        && OSSL_PROVIDER_load(NULL, prov) == NULL) {
        fprintf(stderr, "evp_legacy: %s provider unavailable\n", prov);
        return 2;
    }
    md = EVP_MD_fetch(NULL, dig_name, propquery);
    if (md == NULL) {
        fprintf(stderr, "evp_legacy: spike fetch failed\n");
        return 2;
    }
    fprintf(stderr, "provider[digest]=%s\n",
        OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)));
    memset(input, 0xA5, sizeof input);
    if (run_digest(md, n) != 0 || run_des(k) != 0)
        return 1;
    fprintf(stderr, "N=%ld\nCALLBACKS=%ld\nLEGACYDONE ops=%ld\n",
        n, 3L * n, k);

    printf("%ld\n", n);
    fflush(stdout);
    /* GO2 retrigger: refetch in a fresh libctx (re-fires the provider
     * query deterministically post-attach) + one more digest iter and
     * DES call, then EOF. */
    rc = want_go("GO2");
    if (rc < 0)
        return 0;
    if (rc != 0)
        return 1;
    {
        OSSL_LIB_CTX *ctx2 = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *p2 = NULL;
        EVP_MD *md2 = NULL;

        if (ctx2 != NULL) {
            p2 = OSSL_PROVIDER_load(ctx2, prov);
            md2 = EVP_MD_fetch(ctx2, dig_name, propquery);
        }
        if (p2 == NULL || md2 == NULL) {
            fprintf(stderr, "evp_legacy: GO2 refetch failed\n");
            EVP_MD_free(md2);
            OSSL_LIB_CTX_free(ctx2);
            return 2;
        }
        EVP_MD_free(md2);
        OSSL_LIB_CTX_free(ctx2);
    }
    if (run_digest(md, 1) != 0 || run_des(1) != 0)
        return 1;
    fprintf(stderr, "REFETCH2=ok\n");
    if (want_go("EOF") < 0)
        return 0;
    return 0;
}
