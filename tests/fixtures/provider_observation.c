/* SPDX-License-Identifier: GPL-3.0-or-later
 * Owned standalone stimulus application with explicit pipe acknowledgements.
 * No observer code is linked or injected into this process. */
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

/* Whole decimal line, bounded independently of the observer. */
static int read_calls(unsigned long *calls) {
    char line[64], *end;
    if (!fgets(line, sizeof(line), stdin) || !strchr(line, '\n')) return 0;
    char *first = line;
    while (*first == ' ' || *first == '\t') ++first;
    if (*first < '0' || *first > '9') return 0;
    errno = 0;
    *calls = strtoul(first, &end, 10);
    return !errno && *calls <= 1000000 && *end == '\n' && end[1] == '\0';
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) return 3;
    OSSL_provider_init_fn *init = (OSSL_provider_init_fn *)dlsym(module, "OSSL_provider_init");
    void (*mode)(int) = (void (*)(int))dlsym(module, "fixture_mode");
    void (*count_mode)(int) = (void (*)(int))dlsym(module, "fixture_count_mode");
    uint64_t (*count_read)(void) = (uint64_t (*)(void))dlsym(module, "fixture_count_read");
    void (*count_reset)(void) = (void (*)(void))dlsym(module, "fixture_count_reset");
    if (!init || !mode || !count_mode || !count_read || !count_reset) return 4;
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (!ctx) return 5;
    OSSL_PROVIDER *p = NULL;
    const OSSL_ALGORITHM *table = NULL;
    /* Preserve only callable function pointers, never dereference an unqueried
     * table. The owned dlopen reference keeps the module mapped until exit. */
    OSSL_FUNC_digest_init_fn *callbacks[2] = { NULL, NULL };
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
            if (missing) OSSL_PROVIDER_unload(missing);
            break;
        }
        case 'Q': {
            int no_store = 99;
            table = p ? OSSL_PROVIDER_query_operation(p, OSSL_OP_DIGEST, &no_store) : NULL;
            if (table) {
                for (int i = 0; i < 2 && table[i].algorithm_names; ++i) {
                    callbacks[i] = NULL;
                    for (const OSSL_DISPATCH *d = table[i].implementation; d && d->function_id; ++d)
                        if (d->function_id == OSSL_FUNC_DIGEST_INIT) callbacks[i] = OSSL_FUNC_digest_init(d);
                }
            }
            success = table != NULL; queries += success; break;
        }
        case 'G': success = p && OSSL_PROVIDER_get0_dispatch(p) != NULL; break;
        case 'Y':
        case 'J': {
            int no_store = 99;
            success = p && OSSL_PROVIDER_query_operation(p, command == 'Y' ? OSSL_OP_CIPHER : 50001, &no_store) != NULL;
            queries += success;
            break;
        }
        case 'L': {
            uintptr_t (*lookalike)(uintptr_t, uintptr_t, uintptr_t) = dlsym(module, "fixture_lookalike");
            unsigned long calls;
            if (!lookalike || !read_calls(&calls)) return 7;
            success = 1;
            for (unsigned long i = 0; i < calls; ++i) if (lookalike(1, 2, 3) != 6) success = 0;
            break;
        }
        case 'P': count_mode(1); success=1; break;
        case 'D': count_mode(0); success=1; break;
        case 'R': printf("counter %" PRIu64 "\n", count_read()); success=1; break;
        case 'Z': count_reset(); printf("counter %" PRIu64 "\n", count_read()); success=1; break;
        case 'C':
        case 'B': {
            unsigned long calls;
            if (!read_calls(&calls)) return 7;
            OSSL_FUNC_digest_init_fn *callback = callbacks[command == 'B'];
            if (callback) {
                success = 1;
                for (unsigned long i = 0; i < calls; ++i)
                    if (callback(NULL, NULL) != 1) success = 0;
                printf("calls %c %lu %" PRIu64 "\n", command, calls, count_read());
            }
            break;
        }
        case 'U': if (p && table) {OSSL_PROVIDER_unquery_operation(p, OSSL_OP_DIGEST, table);table=NULL;success=1;} break;
        case 'M': mode(3); success=1; break;
        case 'T': mode(4); success=1; break;
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
