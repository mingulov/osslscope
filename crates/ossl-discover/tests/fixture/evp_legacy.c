/* SPDX-License-Identifier: GPL-3.0-or-later */
/* P1 exit-3 TP driver: spike EVP fetch (dispatch trigger) plus the
 * full legacy-tripwire ground truth, all through this binary's PLT
 * (caller-attributed probes must observe exactly these calls):
 *   - low-level DES x K(+1) + SHA256 Init/Update/Final x1 (all lanes)
 *   - RSA_meth_new x1 (all lanes; survives 4.0)
 *   - legacy provider load x1 + MD4 fetch (GO1) + RIPEMD160 fetch
 *     (GO2, deterministically post stage-attach) + digest runs
 *   - ENGINE_by_id/init/register_digests/set_default_digests x1 (3.x
 *     only; 4.0 has no ENGINE API → deterministic engine-less TP
 *     with an ENGINE-SKIP diagnostic, same #if precedent as
 *     fallback_provider.c).
 * Usage: evp_legacy -n N -legacy K (GO1: work, GO2: retrigger +
 * ENGINE block, EOF: exit 0).
 * stdout: exactly "%ld\n" with N. stderr: PID=/provider/N=/CALLBACKS=/
 * LEGACYDONE/ENGINE-DONE (or ENGINE-SKIP) markers. Env:
 * SPIKE_PROV/SPIKE_DIGEST select provider + alg.
 * The ENGINE block runs LAST (after GO2 work): ENGINE_set_default
 * can redirect subsequent EVP digest execution, so nothing crypto
 * follows it. Tripwire counts are call counts, not success counts —
 * only a NULL ENGINE_by_id fails the fixture. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_MAJOR < 4
#include <openssl/engine.h>
#define HAVE_ENGINE 1
#else
#define HAVE_ENGINE 0
#endif

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

static int run_sha256(void)
{
    SHA256_CTX c;
    unsigned char out[32];

    SHA256_Init(&c);
    SHA256_Update(&c, input, sizeof input);
    SHA256_Final(out, &c);
    if (out[0] == 0 && out[31] == 0) {
        fprintf(stderr, "legacy: SHA256 zero (no-op call?)\n");
        return 1;
    }
    return 0;
}

static int run_meth(void)
{
    /* Deliberately leaked (no RSA_meth_free): the free call matches
     * the RSA_ low-level prefix and would add a pkey/rsa=1 tripwire
     * hit — noise on top of the single meth_new ground-truth call. */
    RSA_METHOD *m = RSA_meth_new("OSSLSCOPE-RSA", 0);

    if (m == NULL) {
        fprintf(stderr, "legacy: RSA_meth_new failed\n");
        return 1;
    }
    return 0;
}

static int run_legacy_fetch(const char *alg)
{
    char propquery[64];
    EVP_MD *md;
    int rc;

    snprintf(propquery, sizeof propquery, "provider=legacy");
    md = EVP_MD_fetch(NULL, alg, propquery);
    if (md == NULL) {
        fprintf(stderr, "legacy: %s fetch failed\n", alg);
        return 1;
    }
    rc = run_digest(md, 1);
    EVP_MD_free(md);
    return rc;
}

static int run_legacy_md4(void)
{
    OSSL_PROVIDER *lp = OSSL_PROVIDER_load(NULL, "legacy");

    if (lp == NULL) {
        fprintf(stderr, "legacy: legacy provider unavailable\n");
        return 1;
    }
    return run_legacy_fetch("MD4");
}

#if HAVE_ENGINE
static int run_engine(void)
{
    ENGINE *e = ENGINE_by_id("dynamic");

    if (e == NULL) {
        fprintf(stderr, "legacy: ENGINE_by_id(dynamic) failed\n");
        return 1;
    }
    /* Tripwire counts calls, not success: failures here still fired
     * the probes, so the fixture continues regardless. The engine
     * reference is deliberately leaked (no finish/free): ENGINE_free
     * on the by_id'd dynamic engine double-frees on 3.0.22, and
     * finish/free are class-Other (unprobed) anyway. */
    ENGINE_init(e);
    ENGINE_register_digests(e);
    ENGINE_set_default_digests(e);
    return 0;
}
#endif

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
    if (run_sha256() != 0 || run_meth() != 0)
        return 1;
    if (run_legacy_md4() != 0)
        return 1;
    fprintf(stderr, "N=%ld\nCALLBACKS=%ld\nLEGACYDONE ops=%ld\n",
        n, 3L * n, k);

    printf("%ld\n", n);
    fflush(stdout);
    /* GO2 retrigger: refetch in a fresh libctx (re-fires the provider
     * query deterministically post-attach) + one more digest iter and
     * DES call, then the ENGINE block (3.x), then EOF. */
    rc = want_go("GO2");
    if (rc < 0)
        return 0;
    if (rc != 0)
        return 1;
    {
        OSSL_LIB_CTX *ctx2 = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *p2 = NULL;
        EVP_MD *md2 = NULL;
        const char *dig2_name = getenv("SPIKE_DIGEST2");

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
        /* Second-alg refetch (skip when unset): one more post-attach
         * digest query so GO2 alone covers multi-alg arrays (GO1
         * races the stage-2 attach — same hardening as evp_driver). */
        if (dig2_name != NULL && *dig2_name != '\0') {
            EVP_MD *md2b = EVP_MD_fetch(ctx2, dig2_name, propquery);

            if (md2b == NULL) {
                fprintf(stderr, "evp_legacy: GO2 refetch2 failed\n");
                OSSL_LIB_CTX_free(ctx2);
                return 2;
            }
            EVP_MD_free(md2b);
        }
        OSSL_LIB_CTX_free(ctx2);
    }
    if (run_digest(md, 1) != 0 || run_des(1) != 0)
        return 1;
    /* GO2 legacy re-query (a DIFFERENT legacy-only alg — same-alg
     * fetch would hit the method-store cache without querying): the
     * GO1 MD4 query races the legacy query stage-attach and is
     * routinely missed; GO2 is deterministically post-attach, so
     * executed_calls/algs observe this fetch. No provider load here
     * (loads stay exact). RIPEMD160: legacy-only on 3.x AND 4.x
     * (MD5/SHA1 live in the default provider — verified by fetch). */
    if (run_legacy_fetch("RIPEMD160") != 0)
        return 1;
#if HAVE_ENGINE
    if (run_engine() != 0)
        return 1;
    fprintf(stderr, "ENGINE-DONE by_id=1\n");
#else
    fprintf(stderr, "ENGINE-SKIP=absent (no ENGINE API)\n");
#endif
    fprintf(stderr, "REFETCH2=ok\n");
    if (want_go("EOF") < 0)
        return 0;
    return 0;
}
