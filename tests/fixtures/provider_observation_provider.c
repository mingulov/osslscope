/* SPDX-License-Identifier: GPL-3.0-or-later
 * Independent public ABI fixture: compiled separately from the observer.
 * Deliberately unregistered provider and algorithm spellings. */
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <stddef.h>
#include <stdint.h>
static int volatile_table;
static int reject_init;
static int count_mode;
static uint64_t callback_entries;
static unsigned context;
void fixture_mode(int mode) { volatile_table = mode == 1; reject_init = mode == 2; }
void fixture_count_mode(int enabled) { count_mode = enabled; }
uint64_t fixture_count_read(void) { return callback_entries; }
void fixture_count_reset(void) { callback_entries = 0; }
/* An actual out-of-line callback entry, not a model of an observer count. */
__attribute__((noinline)) static int count_entry(void *ctx, const OSSL_PARAM params[]) {
    (void)ctx; (void)params;
    ++callback_entries;
    return 1;
}
static void *newctx(void *ctx) { return ctx; }
static void freectx(void *ctx) { (void)ctx; }
static int digest_init(void *ctx, const OSSL_PARAM params[]) { (void)ctx; (void)params; return 1; }
static const OSSL_DISPATCH implementation[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))digest_init },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))freectx },
    { 9999, (void (*)(void))digest_init },
    { 0, NULL }
};
static const OSSL_ALGORITHM algorithms[] = {
    { "SHA2-256:SHA256", NULL, implementation, NULL },
    { "PRIVATE-FIXTURE-ALGORITHM-NOT-FOR-TRANSPORT", NULL, implementation, NULL },
    { NULL, NULL, NULL, NULL }
};
/* Two advertisements, exactly one implementation address and one role. */
static const OSSL_DISPATCH count_implementation[] = {
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))count_entry },
    { 0, NULL }
};
static const OSSL_ALGORITHM count_algorithms[] = {
    { "SHA2-256:SHA256", NULL, count_implementation, NULL },
    { "PRIVATE-FIXTURE-ALGORITHM-NOT-FOR-TRANSPORT", NULL, count_implementation, NULL },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM *query(void *ctx, int op, int *no_store) {
    (void)ctx;
    *no_store = volatile_table;
    return op == OSSL_OP_DIGEST ? (count_mode ? count_algorithms : algorithms) : NULL;
}
static void unquery(void *ctx, int op, const OSSL_ALGORITHM *a) { (void)ctx; (void)op; (void)a; }
static void teardown(void *ctx) { (void)ctx; }
static const OSSL_DISPATCH dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))unquery },
    { 0, NULL }
};
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out, void **provctx) {
    (void)handle; (void)in;
    if (reject_init) return 0;
    *out = dispatch; *provctx = &context;
    return 1;
}
