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
static int special_table;
static int count_mode;
static uint64_t callback_entries;
static unsigned context;
void fixture_mode(int mode) { volatile_table = mode == 1; reject_init = mode == 2; special_table = mode; }
void fixture_count_mode(int enabled) { count_mode = enabled; }
uint64_t fixture_count_read(void) { return callback_entries; }
void fixture_count_reset(void) { callback_entries = 0; }
/* An actual out-of-line callback entry, not a model of an observer count. */
__attribute__((noinline)) int fixture_count_entry(void *ctx, const OSSL_PARAM params[]) {
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
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))fixture_count_entry },
    { 70001, (void (*)(void))fixture_count_entry },
    { 0, NULL }
};
static const OSSL_ALGORITHM count_algorithms[] = {
    { "SHA2-256:SHA256", NULL, count_implementation, NULL },
    { "PRIVATE-FIXTURE-ALGORITHM-NOT-FOR-TRANSPORT", NULL, count_implementation, NULL },
    { "PRIVATE-SECOND-UNKNOWN-ALGORITHM", NULL, count_implementation, NULL },
    { NULL, NULL, NULL, NULL }
};
static OSSL_ALGORITHM long_algorithms[514];
static const OSSL_ALGORITHM unreadable_algorithms[] = {
    { (const char *)1, NULL, count_implementation, NULL }, { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM *query(void *ctx, int op, int *no_store) {
    (void)ctx;
    *no_store = volatile_table;
    if (special_table == 3) return unreadable_algorithms;
    if (special_table == 4) {
        for (unsigned i = 0; i < 513; ++i) long_algorithms[i] = count_algorithms[1];
        return long_algorithms;
    }
    return op == OSSL_OP_DIGEST || (count_mode && (op == OSSL_OP_CIPHER || op == 50001)) ? (count_mode ? count_algorithms : algorithms) : NULL;
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

/* ABI-shaped static lookalike: this function is unrelated to OpenSSL, and the
 * deliberately invalid scalar arguments/return are never dereferenceable. */
__attribute__((noinline)) uintptr_t fixture_lookalike(uintptr_t a, uintptr_t b, uintptr_t c) {
    __asm__ volatile("" : "+r"(a), "+r"(b), "+r"(c));
    return a + b + c;
}
__attribute__((used)) const OSSL_DISPATCH lookalike_table[] = {
    { 1027, (void (*)(void))fixture_lookalike }, { 0, NULL }
};
