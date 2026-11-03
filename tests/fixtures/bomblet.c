/* SPDX-License-Identifier: GPL-3.0-or-later
 * Control 6 leg-A stimulus: fork bomblet of N immediate-exit children.
 * argv: [logpath, gopath, count, hold_secs]. Children _exit(0) without
 * exec (pure fork+exit pressure); the parent reaps all (exact oracle)
 * and holds the pid for observation. Links libcrypto (eligible member). */
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int wait_go(const char *path) {
    for (int i = 0; i < 600; ++i) {
        if (access(path, F_OK) == 0) return 1;
        struct timespec tenth = { 0, 100000000L };
        nanosleep(&tenth, NULL);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    const char *logpath = argv[1], *gopath = argv[2];
    int count = atoi(argv[3]), hold = atoi(argv[4]);
    if (count < 1 || count > 65536 || hold < 1 || hold > 120) return 2;
    if (!OPENSSL_init_crypto(0, NULL)) return 3;
    FILE *log = fopen(logpath, "w");
    if (!log) return 4;
    setvbuf(log, NULL, _IONBF, 0);
    fprintf(log, "ready %d\n", (int)getpid());
    if (!wait_go(gopath)) { fprintf(log, "go_timeout\n"); fclose(log); return 5; }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < count; ++i) {
        pid_t c = fork();
        if (c < 0) { fprintf(log, "fork_failed %d\n", i); fclose(log); return 6; }
        if (c == 0) _exit(0);
    }
    int reaped = 0;
    for (;;) {
        int status = 0;
        pid_t p = waitpid(-1, &status, 0);
        if (p < 0) break;
        ++reaped;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    unsigned long long ms = (unsigned long long)(t1.tv_sec - t0.tv_sec) * 1000ull
        + (unsigned long long)(t1.tv_nsec - t0.tv_nsec) / 1000000ull;
    fprintf(log, "bomblet %d %llu\n", reaped, ms);
    sleep((unsigned)hold);
    fprintf(log, "done\n");
    fclose(log);
    return reaped == count ? 0 : 1;
}
