/* SPDX-License-Identifier: GPL-3.0-or-later */
/* T09 decoy FIPS driver: loads the provider named "fips" from an
 * explicit modules dir (argv[1]), fetches DECOY-DIGEST from it, and
 * digests once. The C4 oracle: load name "fips" + filename fips.so
 * must still yield provider_class unknown without a pinned
 * enrollment (see decoy_fips_provider.c).
 *
 * Usage: decoy_fips_driver <modules-dir>
 * stdout: LEDGER + DECOYDONE. stderr: diagnostics. Exit 2 on failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

int main(int argc, char **argv)
{
    OSSL_PROVIDER *p;
    EVP_MD *md;
    unsigned char in[32], out[64];
    unsigned int outlen = 0;
    const char *loaded;

    if (argc != 2) {
        fprintf(stderr, "usage: decoy_fips_driver <modules-dir>\n");
        return 2;
    }
    /* Before any libcrypto call: the module search reads it lazily. */
    if (setenv("OPENSSL_MODULES", argv[1], 1) != 0) {
        fprintf(stderr, "decoy_fips_driver: setenv failed\n");
        return 2;
    }
    memset(in, 0x5A, sizeof in);
    p = OSSL_PROVIDER_load(NULL, "fips");
    if (p == NULL) {
        fprintf(stderr, "decoy_fips_driver: fips load failed\n");
        return 2;
    }
    loaded = OSSL_PROVIDER_get0_name(p);
    md = EVP_MD_fetch(NULL, "DECOY-DIGEST", "provider=fips");
    if (md == NULL) {
        fprintf(stderr, "decoy_fips_driver: DECOY-DIGEST fetch failed\n");
        return 2;
    }
    if (EVP_Digest(in, sizeof in, out, &outlen, md, NULL) <= 0) {
        fprintf(stderr, "decoy_fips_driver: digest failed\n");
        return 2;
    }
    printf("LEDGER op=decoy load_name=%s fetches=1 digests=1\n",
           loaded != NULL ? loaded : "?");
    printf("DECOYDONE rc=0\n");
    EVP_MD_free(md);
    OSSL_PROVIDER_unload(p);
    return 0;
}
