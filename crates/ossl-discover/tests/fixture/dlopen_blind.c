/* dlopen_blind.c — pre-loaded provider blindness (P1 exit-3 dlopen
 * cell). dlopen()s the provider + full load/fetch/digest BEFORE
 * printing PID, then idles through GO1/GO2/EOF. Post-attach the
 * provider is mapped but its init/query already ran → inspect must
 * emit PARTIAL(no-query-trigger) + live-but-quiet legacy (libcrypto
 * IS mapped: zeros, no spurious findings), never COMPLETE-with-zero
 * and never a bail.
 * Usage: dlopen_blind SPIKE_SO (GO1, GO2, EOF on stdin; exit 0).
 * Env: SPIKE_PROV/SPIKE_DIGEST select provider + alg. */
#include <dlfcn.h>
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
        fprintf(stderr, "dlopen_blind: want %s\n", want);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *prov, *dig_name;
    char propquery[128];
    OSSL_PROVIDER *p;
    EVP_MD *md;
    void *h;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: dlopen_blind SPIKE_SO\n");
        return 1;
    }
    /* Everything crypto happens pre-PID (invisible by construction). */
    h = dlopen(argv[1], RTLD_NOW);
    if (h == NULL) {
        fprintf(stderr, "dlopen_blind: dlopen: %s\n", dlerror());
        return 2;
    }
    prov = getenv("SPIKE_PROV");
    if (prov == NULL || *prov == '\0')
        prov = "spike";
    dig_name = getenv("SPIKE_DIGEST");
    if (dig_name == NULL || *dig_name == '\0')
        dig_name = "SPIKE-SHA";
    snprintf(propquery, sizeof propquery, "provider=%s", prov);
    p = OSSL_PROVIDER_load(NULL, prov);
    if (p == NULL) {
        fprintf(stderr, "dlopen_blind: %s load failed\n", prov);
        return 2;
    }
    md = EVP_MD_fetch(NULL, dig_name, propquery);
    if (md == NULL || run_digest(md) != 0) {
        fprintf(stderr, "dlopen_blind: pre-PID fetch/digest failed\n");
        return 2;
    }
    EVP_MD_free(md);
    fprintf(stderr, "PRELOAD=ok\n");
    fprintf(stderr, "PID=%d\n", (int)getpid());
    rc = want_go("GO1");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    fprintf(stderr, "DLOPEN1=ok\n");
    rc = want_go("GO2");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    fprintf(stderr, "REFETCH2=ok\n");
    if (want_go("EOF") < 0)
        return 0;
    return 0;
}
