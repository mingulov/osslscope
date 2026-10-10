/* SPDX-License-Identifier: GPL-3.0-or-later */
/* T09 ordinary-ops driver: one single-fetch operation per mode against
 * real default/legacy providers, with an independent fixture-side
 * ledger. Fetched algorithm names alone are NOT the oracle: the C4
 * `ordinary` oracle asserts the observer attributes >=1 EXECUTED site
 * whose candidate classes include the ledgered operation, and that
 * ledgered fetch/op counts explain (lower-bound) observed execution.
 * Exact provider-internal callback counts are implementation-defined
 * and recorded, never asserted.
 *
 * Usage: ordinary_ops_driver {ecdsa|keyexch|kdf|kem|md4|mixed} [--loop SECS]
 * stdout: LEDGER lines + ORDDONE. stderr: diagnostics. Exit 2 on
 * provider/fetch failures; exit 0 with LEDGER skipped=1 on the
 * version-gated kem mode below OpenSSL 3.5 (deterministic skip).
 * Fast by design (no GO gating): exercises the observer's fast-
 * command startup-gap honesty as well as ordinary coverage.
 * With --loop SECS the mode repeats for SECS seconds with a FRESH
 * library context per iteration: fetch caching would otherwise
 * collapse the whole loop to a single provider query (one sampled
 * slot), while fresh contexts re-query every iteration so sampling
 * converges and sustained execution is observable. Each iteration
 * keeps the single-fetch LEDGER shape; a final LEDGER carries the
 * loop totals. The kem version gate runs once (no loop).
 * Iterations are paced ~2/s (usleep 500ms): unpaced iterations
 * livelock the one-slot harvest walk (restart-at-0 on every new
 * query outruns walk completion), collapsing to 0 converged sites.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static const unsigned char input[64] = { 0xA5 };
static unsigned long fetches = 0;
/* Active library context (NULL = default): one-shot modes run on the
 * default context exactly as before; --loop installs a fresh context
 * per iteration so every iteration re-queries. */
static OSSL_LIB_CTX *G_LC = NULL;

static int fail(const char *what)
{
    fprintf(stderr, "ordinary_ops_driver: %s failed\n", what);
    return 2;
}

static int do_ecdsa(void)
{
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(G_LC, "ECDSA", NULL);
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *vctx = NULL;
    unsigned char s[256];
    size_t slen = sizeof s; /* one-shot sign reads the buffer size */
    int signs = 0, verifies = 0, rc = 2;

    if (sig == NULL)
        return fail("ECDSA fetch");
    fetches++;
    EVP_SIGNATURE_free(sig);
    pkey = EVP_PKEY_Q_keygen(G_LC, NULL, "EC", "P-256");
    if (pkey == NULL)
        return fail("EC keygen");
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        return fail("MD_CTX_new");
    if (EVP_DigestSignInit_ex(mctx, NULL, "SHA256", NULL, NULL, pkey, NULL) <= 0
        || EVP_DigestSign(mctx, s, &slen, input, sizeof input) <= 0)
        goto out;
    signs = 1;
    if (EVP_DigestVerifyInit_ex(mctx, NULL, "SHA256", NULL, NULL, pkey, NULL) <= 0
        || EVP_DigestVerify(mctx, s, slen, input, sizeof input) <= 0)
        goto out;
    verifies = 1;
    rc = 0;
out:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_free(pkey);
    printf("LEDGER mode=ecdsa fetches=%lu signs=%d verifies=%d\n", fetches, signs, verifies);
    return rc;
}

static int do_keyexch(void)
{
    EVP_KEYEXCH *ex = EVP_KEYEXCH_fetch(G_LC, "X25519", NULL);
    EVP_PKEY *a = NULL, *b = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[64];
    size_t secretlen = sizeof secret;
    int derives = 0, rc = 2;

    if (ex == NULL)
        return fail("X25519 keyexch fetch");
    fetches++;
    EVP_KEYEXCH_free(ex);
    a = EVP_PKEY_Q_keygen(G_LC, NULL, "X25519");
    b = EVP_PKEY_Q_keygen(G_LC, NULL, "X25519");
    if (a == NULL || b == NULL)
        return fail("X25519 keygen");
    ctx = EVP_PKEY_CTX_new_from_pkey(G_LC, a, NULL);
    if (ctx == NULL
        || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, b) <= 0
        || EVP_PKEY_derive(ctx, secret, &secretlen) <= 0)
        goto out;
    derives = 1;
    rc = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    printf("LEDGER mode=keyexch fetches=%lu derives=%d\n", fetches, derives);
    return rc;
}

static int do_kdf(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(G_LC, "HKDF", NULL);
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[6], *p = params;
    unsigned char key[16], salt[16], info[8], out[32];
    size_t outlen = sizeof out;
    int derives = 0, rc = 2;

    memset(key, 0x0B, sizeof key);
    if (kdf == NULL)
        return fail("HKDF fetch");
    fetches++;
    ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL)
        return fail("HKDF ctx");
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof key);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof salt);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof info);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(ctx, out, outlen, params) <= 0)
        goto out;
    derives = 1;
    rc = 0;
out:
    EVP_KDF_CTX_free(ctx);
    printf("LEDGER mode=kdf fetches=%lu derives=%d\n", fetches, derives);
    return rc;
}

#if OPENSSL_VERSION_MAJOR > 3 || (OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR >= 5)
static int do_kem(void)
{
    EVP_KEM *kem = EVP_KEM_fetch(G_LC, "ML-KEM-768", NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char ct[2048], ss1[64], ss2[64];
    size_t ctlen = sizeof ct, ss1len = sizeof ss1, ss2len = sizeof ss2;
    int encaps = 0, decaps = 0, rc = 2;

    if (kem == NULL)
        return fail("ML-KEM-768 fetch");
    fetches++;
    EVP_KEM_free(kem);
    pkey = EVP_PKEY_Q_keygen(G_LC, NULL, "ML-KEM-768");
    if (pkey == NULL)
        return fail("ML-KEM-768 keygen");
    ctx = EVP_PKEY_CTX_new_from_pkey(G_LC, pkey, NULL);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss1, &ss1len) <= 0)
        goto out;
    encaps = 1;
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, ss2, &ss2len, ct, ctlen) <= 0)
        goto out;
    if (ss1len != ss2len || memcmp(ss1, ss2, ss1len) != 0) {
        fprintf(stderr, "ordinary_ops_driver: KEM secrets mismatch\n");
        goto out;
    }
    decaps = 1;
    rc = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    printf("LEDGER mode=kem fetches=%lu encaps=%d decaps=%d\n", fetches, encaps, decaps);
    return rc;
}
#else
static int do_kem(void)
{
    printf("LEDGER mode=kem skipped=old-openssl\n");
    return 0;
}
#endif

static int run_digest(const char *name, const char *propq)
{
    EVP_MD *md = EVP_MD_fetch(G_LC, name, propq);
    unsigned char out[64];
    unsigned int outlen = 0;
    int digests = 0, rc = 2;

    if (md == NULL)
        return fail(name);
    fetches++;
    if (EVP_Digest(input, sizeof input, out, &outlen, md, NULL) <= 0)
        goto out;
    digests = 1;
    rc = 0;
out:
    EVP_MD_free(md);
    printf("LEDGER digest=%s fetches=%lu digests=%d\n", name, fetches, digests);
    return rc;
}

static int do_md4(void)
{
    OSSL_PROVIDER *lp = OSSL_PROVIDER_load(G_LC, "legacy");
    int rc;

    if (lp == NULL)
        return fail("legacy load");
    printf("LEDGER mode=md4 legacy_loads=1\n");
    rc = run_digest("MD4", "provider=legacy");
    OSSL_PROVIDER_unload(lp);
    return rc;
}

static int do_mixed(void)
{
    OSSL_PROVIDER *lp;
    int rc;

    /* Default-provider SHA2-256 first, then legacy MD4 in one window. */
    rc = run_digest("SHA2-256", "provider=default");
    if (rc != 0)
        return rc;
    lp = OSSL_PROVIDER_load(G_LC, "legacy");
    if (lp == NULL)
        return fail("legacy load");
    printf("LEDGER mode=mixed legacy_loads=1\n");
    rc = run_digest("MD4", "provider=legacy");
    OSSL_PROVIDER_unload(lp);
    return rc;
}

static int run_mode(const char *mode)
{
    if (strcmp(mode, "ecdsa") == 0)
        return do_ecdsa();
    if (strcmp(mode, "keyexch") == 0)
        return do_keyexch();
    if (strcmp(mode, "kdf") == 0)
        return do_kdf();
    if (strcmp(mode, "kem") == 0)
        return do_kem();
    if (strcmp(mode, "md4") == 0)
        return do_md4();
    if (strcmp(mode, "mixed") == 0)
        return do_mixed();
    return -1;
}

int main(int argc, char **argv)
{
    const char *mode;
    long loop_secs = 0;
    int rc;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: ordinary_ops_driver {ecdsa|keyexch|kdf|kem|md4|mixed} [--loop SECS]\n");
        return 2;
    }
    mode = argv[1];
    if (strcmp(mode, "ecdsa") != 0 && strcmp(mode, "keyexch") != 0
        && strcmp(mode, "kdf") != 0 && strcmp(mode, "kem") != 0
        && strcmp(mode, "md4") != 0 && strcmp(mode, "mixed") != 0) {
        fprintf(stderr, "ordinary_ops_driver: unknown mode %s\n", mode);
        return 2;
    }
    if (argc == 4) {
        if (strcmp(argv[2], "--loop") != 0) {
            fprintf(stderr, "usage: ordinary_ops_driver MODE [--loop SECS]\n");
            return 2;
        }
        loop_secs = atol(argv[3]);
        if (loop_secs <= 0 || loop_secs > 3600) {
            fprintf(stderr, "ordinary_ops_driver: bad --loop %s\n", argv[3]);
            return 2;
        }
    } else if (argc == 3) {
        fprintf(stderr, "usage: ordinary_ops_driver MODE [--loop SECS]\n");
        return 2;
    }
#if OPENSSL_VERSION_MAJOR > 3 || (OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR >= 5)
    (void)0;
#else
    /* Below 3.5 the kem mode is a deterministic skip: looping it
     * would spin LEDGER-skipped lines for the whole window. */
    if (loop_secs > 0 && strcmp(mode, "kem") == 0)
        loop_secs = 0;
#endif
    if (loop_secs <= 0) {
        rc = run_mode(mode);
        printf("ORDDONE mode=%s rc=%d\n", mode, rc);
        return rc;
    }
    {
        time_t deadline = time(NULL) + loop_secs;
        unsigned long ops = 0;

        /* Sustained: a fresh context per iteration defeats fetch
         * caching, so every iteration queries and sampling converges.
         * The default provider loads per context; modes needing
         * legacy load it themselves (as in one-shot). */
        rc = 0;
        while (time(NULL) < deadline) {
            OSSL_PROVIDER *dp;

            G_LC = OSSL_LIB_CTX_new();
            if (G_LC == NULL) {
                fprintf(stderr, "ordinary_ops_driver: libctx new failed\n");
                rc = 2;
                break;
            }
            dp = OSSL_PROVIDER_load(G_LC, "default");
            if (dp == NULL) {
                fprintf(stderr, "ordinary_ops_driver: default load failed\n");
                OSSL_LIB_CTX_free(G_LC);
                G_LC = NULL;
                rc = 2;
                break;
            }
            rc = run_mode(mode);
            /* Mode-owned legacy providers unload inside the mode;
             * the default provider frees with the context. */
            OSSL_LIB_CTX_free(G_LC);
            G_LC = NULL;
            if (rc != 0)
                break;
            ops++;
            /* Paced ~2 iters/s: the harvest walk restarts at slot 0
             * on every new query, so a tight loop livelocks it (new
             * queries land before any walk completes — 0 sites).
             * 500ms spacing lets each walk finish (T14r4). */
            usleep(500000);
        }
        printf("LEDGER mode=%s loop_secs=%ld ops=%lu fetches=%lu\n", mode,
               loop_secs, ops, fetches);
        printf("ORDDONE mode=%s rc=%d\n", mode, rc);
        return rc;
    }
}
