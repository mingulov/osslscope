/* config_blind.c — config-selected provider blindness (P1 exit-3
 * config cell). The provider auto-loads via openssl.cnf (OPENSSL_CONF
 * = argv[1], gate-generated, spike by absolute module path) + a
 * fetch/digest BEFORE PID, then idles through GO1/GO2/EOF. Same
 * expectation as dlopen_blind: PARTIAL(no-query-trigger) +
 * live-but-quiet legacy. OPENSSL_CONF is set as the first statement
 * (before any libcrypto use — config loads lazily at first init).
 * Usage: config_blind SPIKE_CNF (GO1, GO2, EOF on stdin; exit 0). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static int run_digest(EVP_MD *md)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char in[64], out[64];
    unsigned int outl = 0;
    int ok;

    if (ctx == NULL)
        return 1;
    memset(in, 0x5A, sizeof in);
    ok = EVP_DigestInit_ex2(ctx, md, NULL)
        && EVP_DigestUpdate(ctx, in, sizeof in)
        && EVP_DigestFinal_ex(ctx, out, &outl);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : 1;
}

static int want_go(const char *want)
{
    char line[16];

    if (fgets(line, sizeof line, stdin) == NULL)
        return -1;
    if (strcmp(line, "GO\n") != 0) {
        fprintf(stderr, "config_blind: want %s\n", want);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *prov, *dig_name;
    char propquery[128];
    EVP_MD *md;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: config_blind SPIKE_CNF\n");
        return 1;
    }
    if (setenv("OPENSSL_CONF", argv[1], 1) != 0) {
        fprintf(stderr, "config_blind: setenv failed\n");
        return 1;
    }
    /* Config auto-load + full use pre-PID (invisible by construction).
     * No OSSL_PROVIDER_load call: selection is purely by config. */
    prov = getenv("SPIKE_PROV");
    if (prov == NULL || *prov == '\0')
        prov = "spike";
    dig_name = getenv("SPIKE_DIGEST");
    if (dig_name == NULL || *dig_name == '\0')
        dig_name = "SPIKE-SHA";
    snprintf(propquery, sizeof propquery, "provider=%s", prov);
    if (!OSSL_PROVIDER_available(NULL, prov)) {
        fprintf(stderr, "config_blind: %s not config-available\n", prov);
        return 2;
    }
    md = EVP_MD_fetch(NULL, dig_name, propquery);
    if (md == NULL || run_digest(md) != 0) {
        fprintf(stderr, "config_blind: pre-PID fetch/digest failed\n");
        return 2;
    }
    EVP_MD_free(md);
    fprintf(stderr, "PRELOAD=ok\n");
    fprintf(stderr, "PID=%d\n", (int)getpid());
    rc = want_go("GO1");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    fprintf(stderr, "CONFIG1=ok\n");
    rc = want_go("GO2");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    fprintf(stderr, "REFETCH2=ok\n");
    if (want_go("EOF") < 0)
        return 0;
    return 0;
}
