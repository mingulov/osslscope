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
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

static pid_t fixture_tid(void) {
#ifdef SYS_gettid
    return (pid_t)syscall(SYS_gettid);
#else
    return getpid();
#endif
}
static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}
static volatile pid_t churn_tid = 0;
static void *churn_worker(void *arg) {
    (void)arg;
    churn_tid = fixture_tid();
    return NULL;
}
/* 6A observed crypto (F13/F14): workers call REAL libcrypto EVP
 * (`EVP_DigestInit_ex2`) with a digest fetched from the fixture
 * provider in the private ctx. Each counted call passes BOTH
 * planes exactly once: the libcrypto EVP entry (provider-plane
 * operational site -> transient per-tid API_THREADS rows) and the
 * fixture provider's digest_init (focused-plane probed site ->
 * ADMITTED/COUNTS). D-record correspondence: one site passage
 * per plane per call (re-init fast path: no newctx/freectx per
 * call -- verified; pool mdctxs are primed in `I`). K/C/B share
 * pool slot 0 SEQUENTIALLY (fixture cmd loop is one-at-a-time);
 * spin thread i uses slot 1+i (never shared). count_mode MUST
 * be 0 (`P` NOT sent): the probed site is the plain digest_init,
 * while count mode serves fixture_count_entry (unprobed).
 */
#define EVP_POOL 1025
static EVP_MD *g_md = NULL;
static EVP_MD_CTX *g_pool[EVP_POOL] = { NULL };
struct crypto_churn_arg {
    int calls_each;
    int done;
};
static void *crypto_churn_worker(void *arg) {
    struct crypto_churn_arg *a = (struct crypto_churn_arg *)arg;
    int done = 0;
    for (int i = 0; i < a->calls_each; i++) {
        if (EVP_DigestInit_ex2(g_pool[0], g_md, NULL) == 1) done++;
    }
    a->done = done;
    churn_tid = fixture_tid();
    return NULL;
}
/* 6A spin worker (F13/F14 oracle): calls the queried provider
 * callback back-to-back until the wall-clock deadline, counting
 * rc-checked completions. All spinners run CONCURRENTLY (spawned
 * first, joined after) so their transient API_THREADS rows overlap
 * and the harness can observe tid rows mid-flight. The exact
 * completed count (not the duration) is N -- timing varies,
 * accounting does not.
 */
struct spin_arg {
    unsigned long long deadline_ns;
    EVP_MD_CTX *mdctx;
    long done;
    pid_t tid;
};
static void *spin_worker(void *arg) {
    struct spin_arg *a = (struct spin_arg *)arg;
    long done = 0;
    a->tid = fixture_tid();
    for (;;) {
        for (int i = 0; i < 64; i++)
            if (EVP_DigestInit_ex2(a->mdctx, g_md, NULL) == 1) done++;
        if (now_ns() >= a->deadline_ns) break;
    }
    a->done = done;
    return NULL;
}

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
    if (argc != 2 && argc != 3) return 2;
    /* Optional finite-test command FIFO for held owned-startup controls. */
    if (argc == 3 && !freopen(argv[2], "r", stdin)) return 2;
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
    /* The owned dlopen reference keeps the module mapped until exit. */
    OSSL_FUNC_digest_init_fn *callbacks[2] = { NULL, NULL };
    /* Counted-crypto mechanism by provider count mode: mode 0 runs
     * EVP re-inits (6A correspondence: one site passage per plane
     * per call); mode 1 runs DIRECT calls through the queried
     * callbacks (physical-entry counting: the counting entry
     * increments per call). Tracked locally (`P`/`D` set it). */
    int app_count_mode = 0;
    int loads = 0, failures = 0, queries = 0, registrations = 0, unloads = 0;
    /* Counted crypto (C/B/K/A) runs EVP re-inits (pool, `I`);
     * Q only validates the queried table shape. */
    puts("ready"); fflush(stdout);
    int command;
    while ((command = getchar()) != EOF && command != 'E') {
        int success = 0;
        if (command == '\n') continue;
        switch(command) {
        case 'I': {
            /* Load the provider AND arm the EVP pool (fetch the
             * digest from the private ctx -- the ONLY provider
             * there, so no property needed -- then create + prime
             * every pool mdctx). All arming passages (fetch-time
             * newctx, prime inits) run here in setup,
             * pre-observer: the stimulus window later holds ONLY
             * the N counted re-inits (digest_init exactly once
             * each, no newctx/freectx). */
            registrations += OSSL_PROVIDER_add_builtin(ctx, "private-fixture-provider", init) == 1;
            p = OSSL_PROVIDER_load(ctx, "private-fixture-provider");
            success = p != NULL;
            loads += success;
            /* Opportunistic EVP arming (mode 0): fetch the digest
             * from the private ctx, create + prime the pool. All
             * arming passages run here in setup. Failures leave
             * the pool disarmed (EVP crypto refuses later); the
             * load itself still succeeds (base semantics). */
            if (p && !g_md) g_md = EVP_MD_fetch(ctx, "SHA256", NULL);
            if (p && g_md) {
                int i;
                for (i = 0; i < EVP_POOL; ++i) {
                    if (!g_pool[i]) g_pool[i] = EVP_MD_CTX_new();
                    if (!g_pool[i] || EVP_DigestInit_ex2(g_pool[i], g_md, NULL) != 1) break;
                }
            }
            break;
        }
        case 'F': {
            OSSL_PROVIDER *missing = OSSL_PROVIDER_load(ctx, "private-fixture-absent");
            success = missing == NULL; failures += success;
            if (missing) OSSL_PROVIDER_unload(missing);
            break;
        }
        case 'Q': {
            int no_store = 99;
            table = p ? OSSL_PROVIDER_query_operation(p, OSSL_OP_DIGEST, &no_store) : NULL;
            /* Shape check + callback capture: every named
             * algorithm carries a digest_init; the first two
             * INIT pointers feed count-mode direct crypto. */
            if (table) {
                int inits = 0, algs = 0;
                callbacks[0] = NULL;
                callbacks[1] = NULL;
                for (int i = 0; table[i].algorithm_names; ++i) {
                    algs++;
                    for (const OSSL_DISPATCH *d = table[i].implementation; d && d->function_id; ++d)
                        if (d->function_id == OSSL_FUNC_DIGEST_INIT) {
                            inits++;
                            if (i < 2) callbacks[i] = OSSL_FUNC_digest_init(d);
                        }
                }
                success = algs > 0 && inits >= algs;
            }
            queries += success; break;
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
        case 'P': count_mode(1); app_count_mode = 1; success=1; break;
        case 'D': count_mode(0); app_count_mode = 0; success=1; break;
        case 'R': printf("counter %" PRIu64 "\n", count_read()); success=1; break;
        case 'Z': count_reset(); printf("counter %" PRIu64 "\n", count_read()); success=1; break;
        case 'C':
        case 'B': {
            unsigned long calls;
            if (!read_calls(&calls)) return 7;
            if (!app_count_mode && g_md && g_pool[0]) {
                /* Mode 0: main-thread EVP re-inits (pool slot 0,
                 * primed in `I`): one digest_init passage per
                 * call. `calls <cmd> <requested> <completed>
                 * <ns>` (6A N oracle). */
                unsigned long done = 0;
                success = 1;
                for (unsigned long i = 0; i < calls; ++i)
                    if (EVP_DigestInit_ex2(g_pool[0], g_md, NULL) == 1) done++;
                printf("calls %c %lu %lu %llu\n", command, calls, done, now_ns());
                fflush(stdout);
            } else if (app_count_mode) {
                /* Mode 1: DIRECT calls through the queried
                 * callback (`B` uses the second where
                 * present). `calls <cmd> <requested>
                 * <provider-counter>` (physical-entry N). */
                OSSL_FUNC_digest_init_fn *callback = callbacks[command == 'B'];
                if (callback) {
                    success = 1;
                    for (unsigned long i = 0; i < calls; ++i)
                        if (callback(NULL, NULL) != 1) success = 0;
                    printf("calls %c %lu %" PRIu64 "\n", command, calls, count_read());
                    fflush(stdout);
                }
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
        case 'O': {
            /* 6A control 9a: dlopen one more module path mid-observation.
             * The path arrives as a single bounded line; the handle is
             * retained (stays mapped, never re-resolved). */
            char path[512];
            if (!fgets(path, sizeof(path), stdin) || !strchr(path, '\n')) return 7;
            *strchr(path, '\n') = '\0';
            char *first = path;
            while (*first == ' ' || *first == '\t') ++first;
            if (*first == '\0') return 7;
            void *extra = dlopen(first, RTLD_NOW | RTLD_LOCAL);
            success = extra != NULL;
            printf("dlopen %s %d\n", first, success);
            break;
        }
        case 'W': {
            /* 6A control 2: spawn+join K threads (tid churn, no crypto).
             * Each birth+death is logged with its tid. */
            unsigned long threads;
            if (!read_calls(&threads) || threads > 1024) return 7;
            success = 1;
            for (unsigned long i = 0; i < threads; ++i) {
                pthread_t t;
                churn_tid = 0;
                if (pthread_create(&t, NULL, churn_worker, NULL) != 0) { success = 0; break; }
                if (pthread_join(t, NULL) != 0 || churn_tid == 0) { success = 0; break; }
                printf("thread %d\n", (int)churn_tid);
                fflush(stdout);
            }
            break;
        }
        case 'K': {
            /* 6A control 2 (F13/F14): sequential spawn+join of K
             * threads, each performing M EVP re-inits (pool slot
             * 0, one site passage per plane per call) then
             * exiting. Sequential only (shared slot 0).
             * Reads two lines: threads, then calls-each. */
            unsigned long threads, calls_each;
            if (!read_calls(&threads) || threads > 1024) return 7;
            if (!read_calls(&calls_each) || calls_each > 100000) return 7;
            if (!g_md || !g_pool[0]) break;
            success = 1;
            unsigned long done_total = 0;
            for (unsigned long i = 0; i < threads; ++i) {
                struct crypto_churn_arg arg;
                pthread_t t;
                arg.calls_each = (int)calls_each;
                arg.done = 0;
                churn_tid = 0;
                if (pthread_create(&t, NULL, crypto_churn_worker, &arg) != 0) { success = 0; break; }
                if (pthread_join(t, NULL) != 0 || churn_tid == 0) { success = 0; break; }
                done_total += (unsigned long)arg.done;
                printf("thread %d %llu\n", (int)churn_tid, now_ns());
                fflush(stdout);
            }
            printf("calls K %lu %lu\n", threads * calls_each, done_total);
            fflush(stdout);
            break;
        }
        case 'A': {
            /* 6A control 2 (F13/F14 oracle): spin T threads
             * running EVP re-inits back-to-back for M ms (wall
             * deadline), all CONCURRENTLY so their transient
             * API_THREADS rows overlap mid-flight. Reads two
             * lines: threads, then millis. Reports one `thread
             * <tid> <ns>` line per spinner (join order) plus
             * `calls A <done> <done>` (timed spin: every spun
             * call completes -- requested equals completed by
             * construction; the exact count is the stimulus
             * truth). */
            unsigned long threads, ms;
            if (!read_calls(&threads) || threads == 0 || threads > 1024) return 7;
            if (!read_calls(&ms) || ms == 0 || ms > 30000) return 7;
            if (!g_md) break;
            {
                pthread_t *handles = calloc(threads, sizeof(pthread_t));
                struct spin_arg *args = calloc(threads, sizeof(struct spin_arg));
                if (!handles || !args) { free(handles); free(args); break; }
                unsigned long long deadline = now_ns() + ms * 1000000ull;
                unsigned long i, started = 0;
                success = 1;
                for (i = 0; i < threads; ++i) {
                    args[i].deadline_ns = deadline;
                    /* Slot 1+i (primed in `I`): never shared. */
                    args[i].mdctx = (1 + i < EVP_POOL) ? g_pool[1 + i] : NULL;
                    args[i].done = 0;
                    args[i].tid = 0;
                    if (!args[i].mdctx) { success = 0; break; }
                    if (pthread_create(&handles[i], NULL, spin_worker, &args[i]) != 0) {
                        success = 0;
                        break;
                    }
                    started++;
                }
                unsigned long done_total = 0;
                for (i = 0; i < started; ++i) {
                    if (pthread_join(handles[i], NULL) != 0) success = 0;
                    done_total += (unsigned long)args[i].done;
                    printf("thread %d %llu\n", (int)args[i].tid, now_ns());
                    fflush(stdout);
                }
                printf("calls A %lu %lu\n", done_total, done_total);
                fflush(stdout);
                free(handles);
                free(args);
            }
            break;
        }
        default: return 6;
        }
        printf("ack %c %d %d %d %d %d %d\n", command, success, loads, failures, queries, registrations, unloads);
        fflush(stdout);
    }
    /* Clean exit with ZERO libcrypto passages: _exit skips provider
     * unload / libctx free / destructors (whose teardown + allocator
     * calls would otherwise execute probed sites AFTER the stimulus
     * window and over-attribute the sealed segment). The OS reaps;
     * the observer seals on the EXIT edge. */
    _exit(0);
}
