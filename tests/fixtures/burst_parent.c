/* SPDX-License-Identifier: GPL-3.0-or-later
 * Control-1 stimulus: fork-burst 32 short-lived children plus 4 survivors.
 * The parent links libcrypto (eligible member); burst children exec sleep
 * (shorter than the 1s tick); survivors exec `openssl speed` (eligible,
 * outlive one tick). Children stay unreaped (zombies, verifiable triple)
 * until the end: fork log + waitpid accounting are the exact oracle. */
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    const char *logpath = argv[1];
    int hold = atoi(argv[2]);
    const char *gopath = argv[3];
    if (hold < 2 || hold > 60) return 2;
    if (!OPENSSL_init_crypto(0, NULL)) return 3;
    FILE *log = fopen(logpath, "w");
    if (!log) return 4;
    setvbuf(log, NULL, _IONBF, 0);
    fprintf(log, "ready %d\n", (int)getpid());
    for (int waited = 0; waited < 600; ++waited) {
        if (access(gopath, F_OK) == 0) break;
        struct timespec tenth = { 0, 100000000L };
        nanosleep(&tenth, NULL);
        if (waited == 599) { fprintf(log, "go_timeout\n"); fclose(log); return 6; }
    }
    fprintf(log, "go\n");
    for (int i = 0; i < 32; ++i) {
        pid_t c = fork();
        if (c < 0) { fprintf(log, "fork_failed %d\n", i); fclose(log); return 5; }
        if (c == 0) {
            execlp("sleep", "sleep", "0.05", (char *)NULL);
            _exit(127);
        }
        fprintf(log, "burst %d %llu\n", (int)c, now_ns());
    }
    for (int i = 0; i < 4; ++i) {
        pid_t c = fork();
        if (c < 0) { fprintf(log, "fork_failed survivor %d\n", i); fclose(log); return 5; }
        if (c == 0) {
            /* 8s (not 4s): session-open latency eats the early ticks
             * (measured tick cadence ~2-4s under BPF attach load), so
             * 4s survivors die before the first post-admission sample
             * and can never be admitted. 8s spans several ticks yet
             * still dies before the 9s reap (observer duration 10s). */
            execlp("openssl", "openssl", "speed", "-elapsed", "-seconds", "8",
                   "-evp", "SHA512", "-bytes", "64", (char *)NULL);
            _exit(127);
        }
        fprintf(log, "survivor %d %llu\n", (int)c, now_ns());
    }
    fflush(log);
    sleep((unsigned)hold);
    int reaped = 0;
    for (;;) {
        int status = 0;
        pid_t p = waitpid(-1, &status, 0);
        if (p < 0) break;
        fprintf(log, "reap %d %d\n", (int)p, status);
        ++reaped;
    }
    fprintf(log, "done %d\n", reaped);
    fclose(log);
    return reaped == 36 ? 0 : 1;
}
