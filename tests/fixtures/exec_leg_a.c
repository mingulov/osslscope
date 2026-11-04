/* SPDX-License-Identifier: GPL-3.0-or-later
 * Control 3/4 pre-exec leg: instrumented provider caller that execs into
 * the next leg. argv: [logpath, go1path, go2path, provider_path, mode, next,
 * next_args...]. mode: leader|nonleader. Logs pre-exec tid set, executing
 * tid + instant, and the exact pre-exec call count. */
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
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
static void log_tasks(FILE *log) {
    DIR *tasks = opendir("/proc/self/task");
    if (!tasks) { fprintf(log, "tasks ?\n"); return; }
    fprintf(log, "tasks");
    struct dirent *entry;
    while ((entry = readdir(tasks)) != NULL) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9')
            fprintf(log, " %s", entry->d_name);
    }
    fprintf(log, "\n");
    closedir(tasks);
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
    fprintf(g_log, "exec %d %llu\n", (int)leg_tid(), now_ns());
    fflush(g_log);
    fsync(fileno(g_log));
    execv(g_next, g_next_argv);
    _exit(127);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 7) return 2;
    const char *logpath = argv[1], *go1 = argv[2], *go2 = argv[3];
    const char *provider_path = argv[4], *mode = argv[5];
    int nonleader = !strcmp(mode, "nonleader");
    if (strcmp(mode, "leader") && !nonleader) return 2;
    g_next = argv[6];
    g_next_argv = &argv[6];
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
    FILE *log = fopen(logpath, "w");
    if (!log) return 10;
    setvbuf(log, NULL, _IONBF, 0);
    g_log = log;
    /* Observed crypto (F14): EVP re-inits with a digest fetched
     * from the fixture provider (private ctx, sole provider).
     * Fetch + mdctx + prime here at startup (pre-baseline, and
     * pre-attach for leg A): each counted re-init passes one
     * site per plane exactly once. Only the 500 inits run
     * inside the harness baseline window. */
    EVP_MD *evp_md = EVP_MD_fetch(ctx, "SHA256", NULL);
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
    if (!evp_md || !evp_ctx) return 12;
    if (EVP_DigestInit_ex2(evp_ctx, evp_md, NULL) != 1) return 13;
    (void)callback;
    fprintf(log, "ready %d %d\n", (int)getpid(), (int)leg_tid());
    log_tasks(log);
    if (!wait_go(go1)) { fprintf(log, "go1_timeout\n"); return 11; }
    int done_a = 0;
    for (int i = 0; i < 500; ++i)
        if (EVP_DigestInit_ex2(evp_ctx, evp_md, NULL) == 1) done_a++;
    fprintf(log, "calls_a %d\n", done_a);
    pthread_t worker = 0;
    if (nonleader) {
        if (pthread_create(&worker, NULL, worker_exec, NULL) != 0) return 13;
        if (!wait_go(go2)) { fprintf(log, "go2_timeout\n"); return 11; }
        log_tasks(log);
        g_go_exec = 1;
        pthread_join(worker, NULL);
        return 14; /* unreachable: the worker execs */
    }
    if (!wait_go(go2)) { fprintf(log, "go2_timeout\n"); return 11; }
    log_tasks(log);
    fprintf(log, "exec %d %llu\n", (int)leg_tid(), now_ns());
    fflush(log);
    fsync(fileno(log));
    execv(g_next, g_next_argv);
    return 15;
}
