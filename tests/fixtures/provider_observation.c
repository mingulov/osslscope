/* SPDX-License-Identifier: GPL-3.0-or-later
 * Owned standalone stimulus application with explicit pipe acknowledgements.
 * No observer code is linked or injected into this process. */
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) return 3;
    OSSL_provider_init_fn *init = (OSSL_provider_init_fn *)dlsym(module, "OSSL_provider_init");
    void (*mode)(int) = (void (*)(int))dlsym(module, "fixture_mode");
    if (!init || !mode) return 4;
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (!ctx) return 5;
    OSSL_PROVIDER *p = NULL;
    const OSSL_ALGORITHM *table = NULL;
    int loads = 0, failures = 0, queries = 0, registrations = 0, unloads = 0;
    puts("ready"); fflush(stdout);
    int command;
    while ((command = getchar()) != EOF && command != 'E') {
        int success = 0;
        if (command == '\n') continue;
        switch(command) {
        case 'I':
            registrations += OSSL_PROVIDER_add_builtin(ctx, "private-fixture-provider", init) == 1;
            p = OSSL_PROVIDER_load(ctx, "private-fixture-provider");
            success = p != NULL; loads += success; break;
        case 'F': {
            OSSL_PROVIDER *missing = OSSL_PROVIDER_load(ctx, "private-fixture-absent");
            success = missing == NULL; failures += success;
            if (missing) OSSL_PROVIDER_unload(missing); break;
        }
        case 'Q': {
            int no_store = 99;
            table = p ? OSSL_PROVIDER_query_operation(p, OSSL_OP_DIGEST, &no_store) : NULL;
            success = table != NULL; queries += success; break;
        }
        case 'U': if (p && table) {OSSL_PROVIDER_unquery_operation(p, OSSL_OP_DIGEST, table);table=NULL;success=1;} break;
        case 'V': mode(1); success=1; break;
        case 'S': mode(0); success=1; break;
        case 'X': if(p){success=OSSL_PROVIDER_unload(p);unloads+=success;p=NULL;}break;
        case 'H': {
            const OSSL_DISPATCH *out = NULL; void *provctx = NULL;
            mode(2); success = init(NULL,NULL,&out,&provctx)==0;mode(0);break;
        }
        default: return 6;
        }
        printf("ack %c %d %d %d %d %d %d\n", command, success, loads, failures, queries, registrations, unloads);
        fflush(stdout);
    }
    if (p) OSSL_PROVIDER_unload(p);
    OSSL_LIB_CTX_free(ctx);
    dlclose(module);
    return 0;
}
