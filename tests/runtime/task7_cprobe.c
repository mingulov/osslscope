/* Task-7 (5G) observed C workload: exercises operational APIs with no
 * stock-CLI path (59/64/66) and failure legs the CLI cannot induce
 * (check/pubcheck/init/update). Non-stock workload (disclosed caveat);
 * every call uses public libcrypto APIs only. Each mode exits 0 iff the
 * probed call returns the documented value, and prints a marker line the
 * E2E oracle asserts. Built per-lane at test time (cc, lane headers/lib).
 */
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

static const unsigned char DATA[] = "0123456789abcdef";
static const unsigned char KEY16[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

static void hexout(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int qdigest_ok(void) {
    unsigned char md[64]; size_t mdlen = 0;
    int rv = EVP_Q_digest(NULL, "SHA2-256", NULL, DATA, sizeof(DATA)-1, md, &mdlen);
    printf("qdigest_ok rv=%d mdlen=%zu\n", rv, mdlen);
    if (rv == 1) hexout(md, mdlen);
    return rv == 1 && mdlen == 32 ? 0 : 2;
}
static int qdigest_bad(void) {
    unsigned char md[64]; size_t mdlen = 0;
    int rv = EVP_Q_digest(NULL, "NOPE-NOPE", NULL, DATA, sizeof(DATA)-1, md, &mdlen);
    printf("qdigest_bad rv=%d\n", rv);
    return rv == 0 ? 0 : 2;
}
static int qmac_ok(void) {
    unsigned char out[64]; size_t outlen = 0;
    unsigned char *r = EVP_Q_mac(NULL, "HMAC", NULL, "SHA2-256", NULL,
        KEY16, sizeof(KEY16), DATA, sizeof(DATA)-1, out, sizeof(out), &outlen);
    printf("qmac_ok null=%d outlen=%zu\n", r == NULL, outlen);
    if (r != NULL) hexout(out, outlen);
    return r != NULL && outlen == 32 ? 0 : 2;
}
static int qmac_bad(void) {
    unsigned char out[64]; size_t outlen = 0;
    unsigned char *r = EVP_Q_mac(NULL, "NOPE", NULL, "SHA2-256", NULL,
        KEY16, sizeof(KEY16), DATA, sizeof(DATA)-1, out, sizeof(out), &outlen);
    printf("qmac_bad null=%d\n", r == NULL);
    return r == NULL ? 0 : 2;
}
static int nonce_ok(void) {
    unsigned char dummy[8], out[16];
    if (RAND_priv_bytes(dummy, sizeof(dummy)) <= 0) { printf("nonce_ok randbytes=0\n"); return 2; }
    EVP_RAND_CTX *primary = RAND_get0_primary(NULL);
    printf("nonce_ok primarynull=%d\n", primary == NULL);
    if (primary == NULL) return 2;
    int rv = EVP_RAND_nonce(primary, out, sizeof(out));
    printf("nonce_ok rv=%d\n", rv);
    return rv == 1 ? 0 : 2;
}
static int nonce_bad(void) {
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    unsigned char out[16];
    int rc = 2;
    if (rand == NULL) return 2;
    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) goto done;
    {
        int rv = EVP_RAND_nonce(ctx, out, sizeof(out));
        printf("nonce_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
done:
    EVP_RAND_CTX_free(ctx); EVP_RAND_free(rand);
    return rc;
}
static EVP_PKEY *gen_dh_params(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    EVP_PKEY *p = NULL;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_uint("prime-len", &(unsigned int){512});
    params[1] = OSSL_PARAM_construct_end();
    if (ctx == NULL || EVP_PKEY_paramgen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
        EVP_PKEY_paramgen(ctx, &p) <= 0) { p = NULL; }
    EVP_PKEY_CTX_free(ctx);
    return p;
}
static EVP_PKEY *gen_ec_key(void) {
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *ec = NULL;
    if (g == NULL) return NULL;
    if (EVP_PKEY_keygen_init(g) <= 0 ||
        EVP_PKEY_CTX_set_group_name(g, "P-256") <= 0 ||
        EVP_PKEY_keygen(g, &ec) <= 0) { ec = NULL; }
    EVP_PKEY_CTX_free(g);
    return ec;
}
static int copyparams_ok(void) {
    EVP_PKEY *from = gen_dh_params();
    EVP_PKEY *to = EVP_PKEY_new();
    int rc = 2;
    if (from == NULL || to == NULL) { printf("copyparams_ok setup=0\n"); goto done; }
    {
        int rv = EVP_PKEY_copy_parameters(to, from);
        printf("copyparams_ok rv=%d\n", rv);
        rc = rv == 1 ? 0 : 2;
    }
done:
    EVP_PKEY_free(from); EVP_PKEY_free(to);
    return rc;
}
static int copyparams_bad(void) {
    EVP_PKEY *from = gen_dh_params();
    EVP_PKEY *ec = gen_ec_key();
    int rc = 2;
    if (from == NULL || ec == NULL) { printf("copyparams_bad setup=0\n"); goto done; }
    {
        int rv = EVP_PKEY_copy_parameters(ec, from);
        printf("copyparams_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
done:
    EVP_PKEY_free(from); EVP_PKEY_free(ec);
    return rc;
}
static int check_bad(void) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *zero = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *c = NULL;
    int rc = 2;
    if (eckey == NULL || !EC_KEY_generate_key(eckey)) goto done;
    zero = BN_new();
    if (zero == NULL) goto done;
    BN_zero(zero);
    if (!EC_KEY_set_private_key(eckey, zero)) goto done;
    pkey = EVP_PKEY_new();
    if (pkey == NULL || !EVP_PKEY_assign_EC_KEY(pkey, eckey)) goto done;
    eckey = NULL;
    c = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (c == NULL) goto done;
    {
        int rv = EVP_PKEY_check(c);
        printf("check_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
done:
    BN_free(zero); EC_KEY_free(eckey); EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(c);
    return rc;
}
static int pubcheck_bad(void) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *pt = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *c = NULL;
    int rc = 2;
    if (eckey == NULL) goto done;
    pt = EC_POINT_new(EC_KEY_get0_group(eckey));
    if (pt == NULL) goto done;
    if (!EC_POINT_set_to_infinity(EC_KEY_get0_group(eckey), pt)) goto done;
    if (!EC_KEY_set_public_key(eckey, pt)) goto done;
    if (!EC_KEY_set_private_key(eckey, BN_value_one())) goto done;
    pkey = EVP_PKEY_new();
    if (pkey == NULL || !EVP_PKEY_assign_EC_KEY(pkey, eckey)) goto done;
    eckey = NULL;
    c = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (c == NULL) goto done;
    {
        int rv = EVP_PKEY_public_check(c);
        printf("pubcheck_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
done:
    EC_POINT_free(pt); EC_KEY_free(eckey); EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(c);
    return rc;
}
static int signinit_bad(void) {
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    EVP_PKEY *ed = NULL;
    EVP_MD_CTX *c3 = NULL;
    const EVP_MD *sha256 = NULL;
    int rc = 2;
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 ||
        EVP_PKEY_keygen(g, &ed) <= 0 || ed == NULL) goto done;
    sha256 = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    c3 = EVP_MD_CTX_new();
    if (sha256 == NULL || c3 == NULL) goto done;
    {
        int rv = EVP_DigestSignInit(c3, NULL, sha256, NULL, ed);
        printf("signinit_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
done:
    EVP_MD_CTX_free(c3); EVP_MD_free((EVP_MD *)sha256);
    EVP_PKEY_free(ed); EVP_PKEY_CTX_free(g);
    return rc;
}
static int verifyinit_bad(void) {
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    EVP_PKEY *ed = NULL;
    EVP_MD_CTX *c4 = NULL;
    const EVP_MD *sha256 = NULL;
    int rc = 2;
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 ||
        EVP_PKEY_keygen(g, &ed) <= 0 || ed == NULL) goto done;
    sha256 = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    c4 = EVP_MD_CTX_new();
    if (sha256 == NULL || c4 == NULL) goto done;
    {
        int rv = EVP_DigestVerifyInit(c4, NULL, sha256, NULL, ed);
        printf("verifyinit_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
done:
    EVP_MD_CTX_free(c4); EVP_MD_free((EVP_MD *)sha256);
    EVP_PKEY_free(ed); EVP_PKEY_CTX_free(g);
    return rc;
}
static int signupdate_bad(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = 2;
    if (ctx == NULL) return 2;
    {
        int rv = EVP_DigestSignUpdate(ctx, DATA, sizeof(DATA)-1);
        printf("signupdate_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}
static int verifyupdate_bad(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = 2;
    if (ctx == NULL) return 2;
    {
        int rv = EVP_DigestVerifyUpdate(ctx, DATA, sizeof(DATA)-1);
        printf("verifyupdate_bad rv=%d\n", rv);
        rc = rv == 0 ? 0 : 2;
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

/* Size-query-only encapsulation: one NULL-out call, then stop. The E2E
 * pins entries==1 (the query phase pkeyutl performs before allocating). */
static int encap_query(void) {
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    EVP_PKEY *key = NULL;
    EVP_PKEY *pub = NULL;
    EVP_PKEY_CTX *op = NULL;
    size_t ctlen = 0, seclen = 0;
    int rc = 2;
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 ||
        EVP_PKEY_keygen(g, &key) <= 0 || key == NULL) goto done;
    {
        /* Public-only peer for the encap call. */
        unsigned char *der = NULL;
        const unsigned char *p = NULL;
        int len = i2d_PUBKEY(key, NULL);
        if (len <= 0) goto done;
        der = OPENSSL_malloc(len);
        if (der == NULL) goto done;
        p = der;
        {
            unsigned char *w = der;
            if (i2d_PUBKEY(key, &w) != len) { OPENSSL_free(der); goto done; }
        }
        pub = d2i_PUBKEY(NULL, &p, len);
        OPENSSL_free(der);
        if (pub == NULL) goto done;
    }
    op = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    if (op == NULL || EVP_PKEY_encapsulate_init(op, NULL) <= 0) goto done;
    {
        int rv = EVP_PKEY_encapsulate(op, NULL, &ctlen, NULL, &seclen);
        printf("encap_query rv=%d ctlen=%zu seclen=%zu\n", rv, ctlen, seclen);
        rc = rv == 1 && ctlen > 0 && seclen > 0 ? 0 : 2;
    }
done:
    EVP_PKEY_CTX_free(op); EVP_PKEY_free(pub); EVP_PKEY_free(key); EVP_PKEY_CTX_free(g);
    return rc;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: task7_cprobe <mode>\n"); return 2; }
    if (!strcmp(argv[1], "qdigest-ok")) return qdigest_ok();
    if (!strcmp(argv[1], "qdigest-bad")) return qdigest_bad();
    if (!strcmp(argv[1], "qmac-ok")) return qmac_ok();
    if (!strcmp(argv[1], "qmac-bad")) return qmac_bad();
    if (!strcmp(argv[1], "nonce-ok")) return nonce_ok();
    if (!strcmp(argv[1], "nonce-bad")) return nonce_bad();
    if (!strcmp(argv[1], "copyparams-ok")) return copyparams_ok();
    if (!strcmp(argv[1], "copyparams-bad")) return copyparams_bad();
    if (!strcmp(argv[1], "check-bad")) return check_bad();
    if (!strcmp(argv[1], "pubcheck-bad")) return pubcheck_bad();
    if (!strcmp(argv[1], "signinit-bad")) return signinit_bad();
    if (!strcmp(argv[1], "verifyinit-bad")) return verifyinit_bad();
    if (!strcmp(argv[1], "signupdate-bad")) return signupdate_bad();
    if (!strcmp(argv[1], "verifyupdate-bad")) return verifyupdate_bad();
    if (!strcmp(argv[1], "encap-query")) return encap_query();
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
}
