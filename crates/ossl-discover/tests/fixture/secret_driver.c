/* Secret-canary driver (P4 exit 2): pushes KNOWN sentinel buffers
 * through digest/sign/cipher/MAC/KEM/KDF/RAND/password/salt paths
 * while the observer watches. Two sentinel classes (by prefix):
 * CNRY7QZ-* crypto-buffer sentinels must be absent from EVERY
 * artifact including the raw ring dump (probes never read them);
 * CNRY7QN-* trip-arg sentinels traverse the trip string-read site,
 * so they must be PRESENT in the ring dump (alias lane fired) and
 * ABSENT from every classified artifact. Sentinels live only in
 * this binary's rodata and in crypto-call arguments — never in
 * argv/env/stderr (cmdline is allowlisted).
 * Protocol: prints PID=, runs all lanes on GO1, prints CANARYDONE,
 * blocks for GO2/EOF. -threads T runs stack-buffer worker lanes
 * concurrently. Exit 2 on any lane failure. Lanes print LANE <name>
 * ok|skip:<why> (skip only for provably-absent primitives).
 * Build fallbacks (remote script): -DCANARY_NO_KEM,
 * -DCANARY_NO_ENGINE. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#if OPENSSL_VERSION_MAJOR < 4
#include <openssl/engine.h>
#endif

#define S_DIGEST_HEAP "CNRY7QZ-DIGEST-HEAP-01"
#define S_DIGEST_STACK "CNRY7QZ-DIGEST-STACK-02"
#define S_SIGN_MSG "CNRY7QZ-SIGN-MSG-03"
#define S_CIPHER_KEY "CNRY7QZ-CIPHER-KEY-04-KKKKKKKKKKK"
#define S_CIPHER_IV "CNRY7QZ-IV-05"
#define S_CIPHER_PT "CNRY7QZ-CIPHER-PT-06"
#define S_CIPHER_AAD "CNRY7QZ-CIPHER-AAD-07"
#define S_HMAC_KEY "CNRY7QZ-HMAC-KEY-08"
#define S_HMAC_DATA "CNRY7QZ-HMAC-DATA-09"
#define S_KDF_PASS "CNRY7QZ-KDF-PASS-10"
#define S_KDF_SALT "CNRY7QZ-KDF-SALT-11"
#define S_KDF_INFO "CNRY7QZ-KDF-INFO-12"
#define S_PBKDF2_PASS "CNRY7QZ-PBKDF2-PASS-13"
#define S_PBKDF2_SALT "CNRY7QZ-PBKDF2-SALT-14"
#define S_SCRYPT_PASS "CNRY7QZ-SCRYPT-PASS-15"
#define S_SCRYPT_SALT "CNRY7QZ-SCRYPT-SALT-16"
#define S_RAND_SEED "CNRY7QZ-RAND-SEED-17-SEED-SEED"
#define S_PROPQUERY "CNRY7QN-PROPQUERY-18"
#define S_LOAD_NAME "CNRY7QN-LOAD-NAME-19"
#define S_ENGINE_ID "CNRY7QN-ENGINE-ID-20"
#define S_THREAD_A "CNRY7QZ-THREAD-A-21-STACK"
#define S_THREAD_B "CNRY7QZ-THREAD-B-22-STACK"
#define S_THREAD_C "CNRY7QZ-THREAD-C-23-STACK"
#define S_THREAD_D "CNRY7QZ-THREAD-D-24-STACK"

static int fails;

#define LANE_OK(n) do { fprintf(stderr, "LANE %s ok\n", n); } while (0)
#define LANE_FAIL(n) do { fprintf(stderr, "LANE %s FAIL\n", n); fails++; } while (0)
#define LANE_SKIP(n, w) do { fprintf(stderr, "LANE %s skip:%s\n", n, w); } while (0)

/* Heap + stack digest inputs (one-shot + streaming). */
static void lane_digest(void)
{
    unsigned char out[64];
    unsigned int outl = 0;
    char *heap;
    char stack[256];
    EVP_MD_CTX *ctx;

    memset(stack, 0, sizeof stack);
    memcpy(stack, S_DIGEST_STACK, sizeof S_DIGEST_STACK);
    heap = malloc(4096);
    if (heap == NULL) {
        LANE_FAIL("digest");
        return;
    }
    memset(heap, 'H', 4096);
    memcpy(heap + 1000, S_DIGEST_HEAP, sizeof S_DIGEST_HEAP);
    if (!EVP_Digest(heap, 4096, out, &outl, EVP_sha256(), NULL)
        || !EVP_Digest(stack, sizeof stack, out, &outl, EVP_sha256(), NULL)) {
        LANE_FAIL("digest");
        free(heap);
        return;
    }
    /* Streaming update over the stack buffer (aliased 3x). */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL
        || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)
        || !EVP_DigestUpdate(ctx, stack, sizeof stack)
        || !EVP_DigestUpdate(ctx, stack, sizeof stack)
        || !EVP_DigestUpdate(ctx, heap, 4096)
        || !EVP_DigestFinal_ex(ctx, out, &outl)) {
        LANE_FAIL("digest");
    } else {
        LANE_OK("digest");
    }
    EVP_MD_CTX_free(ctx);
    free(heap);
}

/* Sign/verify a sentinel message (fast EC key). */
static void lane_sign(void)
{
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    EVP_MD_CTX *ctx;
    unsigned char sig[256];
    size_t sigl = 0;

    if (pkey == NULL) {
        LANE_FAIL("sign");
        return;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL
        || !EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey)
        || !EVP_DigestSignUpdate(ctx, S_SIGN_MSG, sizeof S_SIGN_MSG)
        || !EVP_DigestSignFinal(ctx, NULL, &sigl)
        || sigl > sizeof sig
        || !EVP_DigestSignFinal(ctx, sig, &sigl)
        || !EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey)
        || !EVP_DigestVerifyUpdate(ctx, S_SIGN_MSG, sizeof S_SIGN_MSG)
        || EVP_DigestVerifyFinal(ctx, sig, sigl) != 1) {
        LANE_FAIL("sign");
    } else {
        LANE_OK("sign");
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

/* AES-256-GCM with sentinel key/IV/plaintext/AAD (roundtrip). */
static void lane_cipher(void)
{
    unsigned char pt[256], ct[256], rt[256], tag[16];
    unsigned char key[32];
    unsigned char iv[12];
    int outl = 0, tmpl = 0;
    EVP_CIPHER_CTX *ctx;

    memset(key, 'K', sizeof key);
    memcpy(key, S_CIPHER_KEY, sizeof S_CIPHER_KEY > 32 ? 32 : sizeof S_CIPHER_KEY);
    memcpy(iv, S_CIPHER_IV, sizeof S_CIPHER_IV > 12 ? 12 : sizeof S_CIPHER_IV);
    memset(pt, 0, sizeof pt);
    memcpy(pt, S_CIPHER_PT, sizeof S_CIPHER_PT);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL
        || !EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)
        || !EVP_EncryptUpdate(ctx, NULL, &outl, (unsigned char *)S_CIPHER_AAD,
                              (int)sizeof S_CIPHER_AAD)
        || !EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)sizeof pt)
        || !EVP_EncryptFinal_ex(ctx, ct + outl, &tmpl)
        || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)
        || !EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)
        || !EVP_DecryptUpdate(ctx, NULL, &outl, (unsigned char *)S_CIPHER_AAD,
                              (int)sizeof S_CIPHER_AAD)
        || !EVP_DecryptUpdate(ctx, rt, &outl, ct, (int)sizeof pt)
        || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)
        || EVP_DecryptFinal_ex(ctx, rt + outl, &tmpl) <= 0
        || memcmp(rt, pt, sizeof pt) != 0) {
        LANE_FAIL("cipher");
    } else {
        LANE_OK("cipher");
    }
    EVP_CIPHER_CTX_free(ctx);
}

/* HMAC with sentinel key over sentinel data. */
static void lane_hmac(void)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    unsigned char out[64];
    size_t outl = 0;
    int ok = 0;

    if (mac != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                     "SHA256", 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                        (void *)S_HMAC_KEY, sizeof S_HMAC_KEY);
        params[2] = OSSL_PARAM_construct_end();
        ctx = EVP_MAC_CTX_new(mac);
        ok = ctx != NULL
            && EVP_MAC_init(ctx, NULL, 0, params)
            && EVP_MAC_update(ctx, (unsigned char *)S_HMAC_DATA,
                              sizeof S_HMAC_DATA)
            && EVP_MAC_final(ctx, out, &outl, sizeof out);
    }
    if (ok)
        LANE_OK("hmac");
    else
        LANE_FAIL("hmac");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

/* KDF (PBKDF2 + HKDF) with sentinel password/salt/info. */
static void lane_kdf(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[6];
    unsigned char out[32];
    size_t outl = sizeof out;
    int ok = 0;

    if (kdf != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                     "SHA256", 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                        (void *)S_KDF_PASS, sizeof S_KDF_PASS);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                        (void *)S_KDF_SALT, sizeof S_KDF_SALT);
        params[3] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &(unsigned int){1000});
        params[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                        (void *)S_KDF_INFO, sizeof S_KDF_INFO);
        params[5] = OSSL_PARAM_construct_end();
        ctx = EVP_KDF_CTX_new(kdf);
        ok = ctx != NULL && EVP_KDF_derive(ctx, out, outl, params) > 0;
    }
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    if (ok)
        LANE_OK("kdf");
    else
        LANE_FAIL("kdf");
}

/* Password KDFs: PBKDF2-HMAC + scrypt, sentinel pass/salt. */
static void lane_password(void)
{
    unsigned char out[32];
    int ok;

    ok = PKCS5_PBKDF2_HMAC(S_PBKDF2_PASS, (int)sizeof S_PBKDF2_PASS,
                           (unsigned char *)S_PBKDF2_SALT,
                           (int)sizeof S_PBKDF2_SALT, 1000,
                           EVP_sha256(), (int)sizeof out, out);
    ok = ok && EVP_PBE_scrypt(S_SCRYPT_PASS, sizeof S_SCRYPT_PASS,
                              (unsigned char *)S_SCRYPT_SALT,
                              sizeof S_SCRYPT_SALT, 1024, 8, 1, 32 << 20,
                              out, sizeof out);
    if (ok)
        LANE_OK("password");
    else
        LANE_FAIL("password");
}

/* RNG seeded with a sentinel, then sampled. */
static void lane_rand(void)
{
    unsigned char buf[64];

    RAND_seed(S_RAND_SEED, (int)sizeof S_RAND_SEED);
    if (RAND_bytes(buf, (int)sizeof buf) == 1
        && RAND_priv_bytes(buf, 32) == 1)
        LANE_OK("rand");
    else
        LANE_FAIL("rand");
}

/* KEM roundtrip (RSA): encapsulate + decapsulate, compare secrets. */
static void lane_kem(void)
{
#ifdef CANARY_NO_KEM
    LANE_SKIP("kem", "CANARY_NO_KEM");
#else
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t ctlen = 0, sslen = 0, ss2len = 0;
    int ok = 0;

    if (pkey == NULL) {
        LANE_FAIL("kem");
        return;
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        /* Primitive absent in this provider build — loud skip. */
        LANE_SKIP("kem", "encapsulate_init-unsupported");
        goto done;
    }
    ok = EVP_PKEY_encapsulate(ctx, NULL, &ctlen, NULL, &sslen) > 0
        && (ct = malloc(ctlen)) != NULL
        && (ss1 = malloc(sslen)) != NULL
        && EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss1, &sslen) > 0
        && EVP_PKEY_decapsulate_init(ctx, NULL) > 0
        && EVP_PKEY_decapsulate(ctx, NULL, &ss2len, ct, ctlen) > 0
        && (ss2 = malloc(ss2len)) != NULL
        && EVP_PKEY_decapsulate(ctx, ss2, &ss2len, ct, ctlen) > 0
        && ss2len == sslen && memcmp(ss1, ss2, sslen) == 0;
    if (ok)
        LANE_OK("kem");
    else
        LANE_FAIL("kem");
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(ct);
    free(ss1);
    free(ss2);
#endif
}

/* Propquery + provider-load alias lanes: sentinel strings through
 * fetch/load entrypoints (expected to FAIL lookup — the tripwire
 * probes fire on entry regardless). */
static void lane_propquery(void)
{
    char pq[128];
    char longname[201];
    EVP_MD *md;
    OSSL_PROVIDER *p;

    snprintf(pq, sizeof pq, "provider=%s", S_PROPQUERY);
    md = EVP_MD_fetch(NULL, "SHA256", pq);
    EVP_MD_free(md);
    p = OSSL_PROVIDER_load(NULL, S_LOAD_NAME);
    if (p != NULL)
        OSSL_PROVIDER_unload(p);
    /* Overlong (200B) load name: trip probe reads 32B only. */
    memset(longname, 'L', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    memcpy(longname, S_LOAD_NAME, sizeof S_LOAD_NAME);
    p = OSSL_PROVIDER_load(NULL, longname);
    if (p != NULL)
        OSSL_PROVIDER_unload(p);
    /* All three must FAIL lookup (unknown names) — else the lane
     * did not isolate the probe path. */
    if (md == NULL)
        LANE_OK("propquery");
    else
        LANE_FAIL("propquery");
}

/* ENGINE_by_id alias lane (3.x only; 4.x removed ENGINE). */
static void lane_engine(void)
{
#if defined(CANARY_NO_ENGINE) || OPENSSL_VERSION_MAJOR >= 4
    LANE_SKIP("engine", "no-ENGINE");
#else
    ENGINE *e = ENGINE_by_id(S_ENGINE_ID);

    if (e != NULL)
        ENGINE_free(e);
    /* Unknown id must fail — the entry probe still fired. */
    if (e == NULL)
        LANE_OK("engine");
    else
        LANE_FAIL("engine");
#endif
}

static const char *thread_sentinels[4] =
    { S_THREAD_A, S_THREAD_B, S_THREAD_C, S_THREAD_D };

/* Concurrent stack-arg lane: digest + HMAC over a stack buffer. */
static void *worker(void *arg)
{
    long idx = (long)arg;
    const char *s = thread_sentinels[idx % 4];
    unsigned char out[64];
    unsigned int outl = 0;
    int i;

    for (i = 0; i < 300; i++) {
        char stack[256];
        EVP_MAC *mac;
        EVP_MAC_CTX *mctx;

        memset(stack, 0, sizeof stack);
        memcpy(stack, s, strlen(s) + 1);
        if (!EVP_Digest(stack, sizeof stack, out, &outl, EVP_sha256(), NULL))
            return (void *)1;
        mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (mac == NULL)
            return (void *)1;
        mctx = EVP_MAC_CTX_new(mac);
        if (mctx == NULL) {
            EVP_MAC_free(mac);
            return (void *)1;
        }
        {
            OSSL_PARAM params[3];

            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                         "SHA256", 0);
            params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                            stack, sizeof stack);
            params[2] = OSSL_PARAM_construct_end();
            if (!EVP_MAC_init(mctx, NULL, 0, params)
                || !EVP_MAC_update(mctx, (unsigned char *)s, strlen(s))
                || !EVP_MAC_final(mctx, out, &(size_t){sizeof out}, sizeof out)) {
                EVP_MAC_CTX_free(mctx);
                EVP_MAC_free(mac);
                return (void *)1;
            }
        }
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(mac);
    }
    return NULL;
}

static int read_go(void)
{
    char line[64];

    if (fgets(line, sizeof line, stdin) == NULL)
        return 0;
    return strncmp(line, "GO", 2) == 0;
}

int main(int argc, char **argv)
{
    int nthreads = 4;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-threads") == 0 && i + 1 < argc)
            nthreads = atoi(argv[++i]);
    }
    printf("PID=%d\n", (int)getpid());
    fflush(stdout);
    if (!read_go())
        return 0;
    /* Workers first: main lanes run while stack sentinels are live. */
    {
        pthread_t *tids = calloc((size_t)(nthreads > 0 ? nthreads : 1),
                                 sizeof *tids);
        int n = nthreads < 1 ? 1 : (nthreads > 16 ? 16 : nthreads);
        int bad = 0;

        if (tids == NULL)
            return 2;
        for (i = 0; i < n; i++) {
            if (pthread_create(&tids[i], NULL, worker, (void *)(long)i) != 0)
                bad = 1;
        }
        lane_digest();
        lane_sign();
        lane_cipher();
        lane_hmac();
        lane_kdf();
        lane_password();
        lane_rand();
        lane_kem();
        lane_propquery();
        lane_engine();
        for (i = 0; i < n; i++) {
            void *rc = NULL;

            if (tids[i] != 0) {
                pthread_join(tids[i], &rc);
                if (rc != NULL)
                    bad = 1;
            }
        }
        free(tids);
        if (bad)
            LANE_FAIL("threads");
        else
            LANE_OK("threads");
    }
    printf("CANARYDONE fails=%d\n", fails);
    fflush(stdout);
    read_go();
    return fails ? 2 : 0;
}
