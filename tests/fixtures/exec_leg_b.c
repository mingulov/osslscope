/* SPDX-License-Identifier: GPL-3.0-or-later
 * Control 3/4 post-exec leg: re-establishes the instrumented provider,
 * waits for the re-admission gate, then performs exact post-exec calls
 * (all post-admission, so the per-leg ADMITTED gates are exact), then
 * either exits or (adversarial leg) execs onward IMMEDIATELY (same-tick
 * double exec: no calls, no gate wait between the two execs).
 * argv: [logpath, provider_path, go3path, go4path, mode, next...].
 * mode: end|exec. Logs post-exec exe identity + exact call counts. */
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static pid_t leg_tid(void) {
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
static int wait_go(const char *path) {
    for (int i = 0; i < 600; ++i) {
        if (access(path, F_OK) == 0) return 1;
        struct timespec tenth = { 0, 100000000L };
        nanosleep(&tenth, NULL);
    }
    return 0;
}

static const char *g_next;
static char **g_next_argv;
static FILE *g_log;
static volatile int g_go_exec = 0;
static void *worker_exec(void *arg) {
    (void)arg;
    while (!g_go_exec) {
        struct timespec spin = { 0, 1000000L };
        nanosleep(&spin, NULL);
    }
    fprintf(g_log, "exec2 %d %llu\n", (int)leg_tid(), now_ns());
    fflush(g_log);
    fsync(fileno(g_log));
    execv(g_next, g_next_argv);
    _exit(127);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 6) return 2;
    const char *logpath = argv[1], *provider_path = argv[2], *go3 = argv[3], *go4 = argv[4];
    int onward = !strcmp(argv[5], "exec");
    if (strcmp(argv[5], "end") && !onward) return 2;
    g_next_argv = onward ? &argv[6] : NULL;
    g_next = onward ? argv[6] : NULL;
    void *module = dlopen(provider_path, RTLD_NOW | RTLD_LOCAL);
    if (!module) return 3;
    OSSL_provider_init_fn *init = (OSSL_provider_init_fn *)dlsym(module, "OSSL_provider_init");
    void (*count_mode)(int) = (void (*)(int))dlsym(module, "fixture_count_mode");
    uint64_t (*count_read)(void) = (uint64_t (*)(void))dlsym(module, "fixture_count_read");
    if (!init || !count_mode || !count_read) return 4;
    /* count_mode 0: the queried callback is the probed plain
     * digest_init (D-record correspondence). */
    count_mode(0);
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    if (!ctx) return 5;
    if (!OSSL_PROVIDER_add_builtin(ctx, "private-fixture-provider", init)) return 6;
    OSSL_PROVIDER *p = OSSL_PROVIDER_load(ctx, "private-fixture-provider");
    if (!p) return 7;
    int no_store = 99;
    const OSSL_ALGORITHM *table = OSSL_PROVIDER_query_operation(p, OSSL_OP_DIGEST, &no_store);
    if (!table) return 8;
    OSSL_FUNC_digest_init_fn *callback = NULL;
    for (int i = 0; i < 2 && table[i].algorithm_names; ++i)
        for (const OSSL_DISPATCH *d = table[i].implementation; d && d->function_id; ++d)
            if (d->function_id == OSSL_FUNC_DIGEST_INIT) callback = OSSL_FUNC_digest_init(d);
    if (!callback) return 9;
    FILE *log = fopen(logpath, "a");
    if (!log) return 10;
    setvbuf(log, NULL, _IONBF, 0);
    g_log = log;
    /* Observed crypto (F14): EVP re-inits with a digest fetched
     * from the fixture provider (private ctx, sole provider).
     * Fetch + mdctx + prime here at startup (pre-b0: startup
     * precedes the postexec sync the harness baselines after);
     * only the 500 post-go3 inits run inside the B window. */
    EVP_MD *evp_md = EVP_MD_fetch(ctx, "SHA256", NULL);
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
    if (!evp_md || !evp_ctx) return 12;
    if (EVP_DigestInit_ex2(evp_ctx, evp_md, NULL) != 1) return 13;
    (void)callback;
    struct stat exe;
    if (stat("/proc/self/exe", &exe) != 0) return 11;
    fprintf(log, "postexec %d %llu %llu\n",
            (int)getpid(), (unsigned long long)exe.st_dev, (unsigned long long)exe.st_ino);
    if (onward) {
        /* Adversarial: exec onward immediately (same tick as the
         * first exec -- no calls, no gate wait between them). */
        pthread_t worker;
        if (pthread_create(&worker, NULL, worker_exec, NULL) != 0) return 13;
        g_go_exec = 1;
        pthread_join(worker, NULL);
        return 15; /* unreachable: the worker execs */
    }
    if (!wait_go(go3)) { fprintf(log, "go3_timeout\n"); return 14; }
    int done_b = 0;
    for (int i = 0; i < 500; ++i)
        if (EVP_DigestInit_ex2(evp_ctx, evp_md, NULL) == 1) done_b++;
    fprintf(log, "calls_b %d %llu\n", done_b, now_ns());
    /* Hold for the harness B-final map dump (deterministic window:
     * the process stays alive with its maps until GO4). */
    if (!wait_go(go4)) { fprintf(log, "go4_timeout\n"); return 14; }
    fprintf(log, "leg_b_done\n");
    fclose(log);
    /* Clean exit with ZERO libcrypto passages: _exit skips exit
     * destructors (whose provider-teardown + allocator calls would
     * otherwise execute probed sites AFTER the stimulus window and
     * over-attribute epoch 1). The observer seals on the EXIT edge. */
    _exit(0);
}
