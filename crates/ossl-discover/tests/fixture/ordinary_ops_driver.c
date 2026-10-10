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
 * Usage: ordinary_ops_driver {ecdsa|keyexch|kdf|kem|md4|mixed}
 * stdout: LEDGER lines + ORDDONE. stderr: diagnostics. Exit 2 on
 * provider/fetch failures; exit 0 with LEDGER skipped=1 on the
 * version-gated kem mode below OpenSSL 3.5 (deterministic skip).
 * Fast by design (no GO gating): exercises the observer's fast-
 * command startup-gap honesty as well as ordinary coverage.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static const unsigned char input[64] = { 0xA5 };
static unsigned long fetches = 0;

static int fail(const char *what)
{
    fprintf(stderr, "ordinary_ops_driver: %s failed\n", what);
    return 2;
}

static int do_ecdsa(void)
{
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "ECDSA", NULL);
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
    pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
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
    EVP_KEYEXCH *ex = EVP_KEYEXCH_fetch(NULL, "X25519", NULL);
    EVP_PKEY *a = NULL, *b = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[64];
    size_t secretlen = sizeof secret;
    int derives = 0, rc = 2;

    if (ex == NULL)
        return fail("X25519 keyexch fetch");
    fetches++;
    EVP_KEYEXCH_free(ex);
    a = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    b = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (a == NULL || b == NULL)
        return fail("X25519 keygen");
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL);
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
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
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
    EVP_KEM *kem = EVP_KEM_fetch(NULL, "ML-KEM-768", NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char ct[2048], ss1[64], ss2[64];
    size_t ctlen = sizeof ct, ss1len = sizeof ss1, ss2len = sizeof ss2;
    int encaps = 0, decaps = 0, rc = 2;

    if (kem == NULL)
        return fail("ML-KEM-768 fetch");
    fetches++;
    EVP_KEM_free(kem);
    pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    if (pkey == NULL)
        return fail("ML-KEM-768 keygen");
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
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
    EVP_MD *md = EVP_MD_fetch(NULL, name, propq);
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
    OSSL_PROVIDER *lp = OSSL_PROVIDER_load(NULL, "legacy");
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
    lp = OSSL_PROVIDER_load(NULL, "legacy");
    if (lp == NULL)
        return fail("legacy load");
    printf("LEDGER mode=mixed legacy_loads=1\n");
    rc = run_digest("MD4", "provider=legacy");
    OSSL_PROVIDER_unload(lp);
    return rc;
}

int main(int argc, char **argv)
{
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: ordinary_ops_driver {ecdsa|keyexch|kdf|kem|md4|mixed}\n");
        return 2;
    }
    if (strcmp(argv[1], "ecdsa") == 0)
        rc = do_ecdsa();
    else if (strcmp(argv[1], "keyexch") == 0)
        rc = do_keyexch();
    else if (strcmp(argv[1], "kdf") == 0)
        rc = do_kdf();
    else if (strcmp(argv[1], "kem") == 0)
        rc = do_kem();
    else if (strcmp(argv[1], "md4") == 0)
        rc = do_md4();
    else if (strcmp(argv[1], "mixed") == 0)
        rc = do_mixed();
    else {
        fprintf(stderr, "ordinary_ops_driver: unknown mode %s\n", argv[1]);
        return 2;
    }
    printf("ORDDONE mode=%s rc=%d\n", argv[1], rc);
    return rc;
}
