/* query_dump.c — ground-truth provider-table census (P1 exit-2 test tool).
 * Loads one provider, calls OSSL_PROVIDER_query_operation per op id, and
 * prints every (op, alg-names, funcid, impl-file-offset) row as TSV.
 * Offsets are file offsets (fptr - dladdr base): ASLR-stable, directly
 * comparable to harvest `backing.offset`. NOT shipped; gate-only.
 * Usage: query_dump <provider>   (OPENSSL_MODULES for out-of-tree modules)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/provider.h>
#include <openssl/core_dispatch.h>

int main(int argc, char **argv)
{
    OSSL_PROVIDER *prov;
    int op, total = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: query_dump <provider>\n");
        return 1;
    }
    prov = OSSL_PROVIDER_load(NULL, argv[1]);
    if (prov == NULL) {
        fprintf(stderr, "query_dump: cannot load %s\n", argv[1]);
        return 1;
    }
    for (op = 1; op <= OSSL_OP__HIGHEST; op++) {
        const OSSL_ALGORITHM *algs;
        int nocache = 0, nalgs = 0;
        algs = OSSL_PROVIDER_query_operation(prov, op, &nocache);
        if (algs == NULL)
            continue;
        for (; algs->algorithm_names != NULL; algs++) {
            const OSSL_DISPATCH *d;
            nalgs++;
            if (algs->implementation == NULL)
                continue;
            for (d = algs->implementation; d->function_id != 0; d++) {
                Dl_info info;
                unsigned long off = 0;
                const char *obj = "?";
                if (d->function != NULL
                    && dladdr((const void *)d->function, &info)
                    && info.dli_fbase != NULL) {
                    off = (unsigned long)d->function
                        - (unsigned long)info.dli_fbase;
                    obj = info.dli_fname ? info.dli_fname : "?";
                }
                printf("%d\t%s\t%d\t%s\t%lx\n", op,
                    algs->algorithm_names, d->function_id, obj, off);
                total++;
            }
        }
        fprintf(stderr, "op=%d algs=%d\n", op, nalgs);
    }
    fprintf(stderr, "TOTAL rows=%d\n", total);
    return 0;
}
