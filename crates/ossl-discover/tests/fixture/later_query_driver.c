/* SPDX-License-Identifier: GPL-3.0-or-later */
/* T03 single-query driver: issues exactly ONE direct
 * query_operation call, then sleeps for the harvest window.
 * Usage: later_query_driver <provider.so> <op-id>
 * stdin: blocks for one GO line (post-attach trigger, evp_driver
 * convention), then calls OSSL_provider_init directly via dlsym
 * (fires INIT_RETURN so userspace installs stage-2), waits 2s for
 * the drain loop to attach, issues ONE query, prints the oracle
 * line, and sleeps 120s (killed by the test/harness).
 * stdout: exactly "ORACLE queries=1 op=<op> no_store=<n> algs=<k>".
 * Exit 2 on provider problems (evp_driver convention).
 * Build: gcc -O2 -Wall -Wextra -o later_query_driver
 *   later_query_driver.c -ldl -lcrypto
 * Provider build: gcc -O2 -Wall -Wextra -shared -fPIC
 *   -o later_slot_provider.so later_slot_provider.c -lcrypto */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

int main(int argc, char **argv)
{
    const char *sop;
    int op;
    char line[64];
    void *h, *provctx = NULL;
    const OSSL_DISPATCH *out = NULL, *d;
    const OSSL_ALGORITHM *algs, *a;
    int no_store = 0, nalgs = 0;
    int (*p_init)(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *,
                  const OSSL_DISPATCH **, void **);
    const OSSL_ALGORITHM *(*query)(void *, int, int *);

    if (argc != 3) {
        fprintf(stderr, "usage: %s <provider.so> <op-id>\n", argv[0]);
        return 2;
    }
    sop = argv[1];
    op = atoi(argv[2]);

    h = dlopen(sop, RTLD_NOW);
    if (h == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }
    p_init = (int (*)(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *,
                      const OSSL_DISPATCH **, void **))
        dlsym(h, "OSSL_provider_init");
    if (p_init == NULL) {
        fprintf(stderr, "dlsym OSSL_provider_init failed: %s\n",
                dlerror());
        return 2;
    }
    if (fgets(line, sizeof line, stdin) == NULL) {
        fprintf(stderr, "EOF before GO\n");
        return 2;
    }
    if (!p_init(NULL, NULL, &out, &provctx) || out == NULL) {
        fprintf(stderr, "provider init failed\n");
        return 2;
    }
    /* Stage-2 window: userspace drains INIT_RETURN and attaches the
     * query pair before the single query fires (400x the 5ms drain
     * quantum; the live lane is not time-pressured). */
    sleep(2);
    query = NULL;
    for (d = out; d->function_id != 0; d++) {
        if (d->function_id == OSSL_FUNC_PROVIDER_QUERY_OPERATION)
            query = (const OSSL_ALGORITHM *(*)(void *, int, int *))
                d->function;
    }
    if (query == NULL) {
        fprintf(stderr, "no query_operation in provider dispatch\n");
        return 2;
    }
    /* THE single query. */
    algs = query(provctx, op, &no_store);
    if (algs == NULL) {
        fprintf(stderr, "query op=%d returned NULL\n", op);
        return 2;
    }
    for (a = algs; a->algorithm_names != NULL; a++)
        nalgs++;
    printf("ORACLE queries=1 op=%d no_store=%d algs=%d\n", op,
           no_store, nalgs);
    fflush(stdout);
    sleep(120);
    return 0;
}
