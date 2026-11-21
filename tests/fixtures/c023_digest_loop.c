// SPDX-License-Identifier: GPL-3.0-or-later
// C023 §6D-10 qual workload: single-threaded EVP_Q_digest loop
// (API 64, SHA2-256 over a fixed 64-byte input). One app op =
// exactly M = 6 intercepted operational edges + F = 1 fetch edge
// (re-derived for OpenSSL 3.5.5; see the Phase 2 report).
//
// Protocol: prints "ready", waits for "W" (warmup: 50 unpaced ops,
// provider load confined here), prints "warmed N", waits for "G"
// (measured run: N paced ops), prints "done completed=N", waits
// for "X", exits 0. Per-op latencies (measured around the op AFTER
// the pace wait) + schedule receipts (completed/wall/max_late/
// origin/checksum) append to the timing file (argv[4]). The
// DELTA-10 completion deadline derives as origin + N × pace.
// Op lines carry their sequence number ("t0 t1 late seq") so the
// parser rejects duplicate/reordered records (P2fix2 item 26).
// C023_FAIL_AT_OP=N fails op N post-emit through the real
// exit-6 + FAILED_AT path (actual child-process failure for the
// shortfall control); the failed child still waits for X (the seal
// takes live custody) and exits 6.
// C023_BUSY_AT_OP=M + C023_BUSY_NS=T (P2fix6 NEW-31): op M
// busy-spins T ns AFTER its own op-only timing closes — a
// controlled scheduling delay so op M+1 starts ~T late (its
// lateness deterministically dominates the run's maximum).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static unsigned char input[64];
static unsigned char md[64];

static int one_op(void) {
    size_t mdlen = 0;
    int ret = EVP_Q_digest(NULL, "SHA2-256", NULL, input, sizeof(input), md, &mdlen);
    if (ret != 1 || mdlen != 32)
        return 0;
    // Bind the output (defeat dead-store elimination honestly: the
    // caller folds the byte into an always-printed checksum).
    return md[0] + 1;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s OPS PACE_NS WARMUP TIMING_FILE\n", argv[0]);
        return 2;
    }
    long ops = atol(argv[1]);
    long long pace_ns = atoll(argv[2]);
    long warmup = atol(argv[3]);
    const char *timing_path = argv[4];
    if (ops <= 0 || pace_ns < 0 || warmup < 0)
        return 2;
    memset(input, 0xA5, sizeof(input));

    printf("ready\n");
    fflush(stdout);
    int ch = getchar();
    if (ch != 'W')
        return 3;
    // Warmup: provider load + fetch-cache settle, OUTSIDE the run.
    long checksum = 0;
    for (long i = 0; i < warmup; i++) {
        int r = one_op();
        if (r == 0) {
            printf("warmup_failed %ld\n", i);
            return 4;
        }
        checksum += r;
    }
    printf("warmed %ld checksum=%ld\n", warmup, checksum);
    fflush(stdout);
    ch = getchar();
    if (ch != 'G')
        return 3;

    FILE *timings = fopen(timing_path, "w");
    if (!timings)
        return 5;
    // Deterministic failure trigger (P2fix2 item 26): fail op N
    // post-emit (all its edges observed — the shortfall arm's
    // exact reachability shape) through the genuine failure path.
    long fail_at = -1;
    const char *fail_env = getenv("C023_FAIL_AT_OP");
    if (fail_env != NULL)
        fail_at = atol(fail_env);
    long busy_at = -1;
    long long busy_ns = 0;
    const char *busy_env = getenv("C023_BUSY_AT_OP");
    const char *busy_ns_env = getenv("C023_BUSY_NS");
    if (busy_env != NULL)
        busy_at = atol(busy_env);
    if (busy_ns_env != NULL)
        busy_ns = atoll(busy_ns_env);
    unsigned long long start = now_ns();
    long completed = 0;
    long long max_late_ns = 0;
    for (long i = 0; i < ops; i++) {
        unsigned long long deadline = start + (unsigned long long)i * (unsigned long long)pace_ns;
        // Offered-load pacing: spin to the op's deadline (pace 0 =
        // unpaced back-to-back).
        while (pace_ns > 0 && (long long)(deadline - now_ns()) > 0)
            ;
        unsigned long long actual = now_ns();
        long long late = (long long)(actual >= deadline ? actual - deadline : 0);
        if (late > max_late_ns)
            max_late_ns = late;
        // Per-op timing starts AFTER the wait (P2fix1: the old t0
        // sat before the spin, so the harness timed pacing, not
        // the op — the frozen estimator needs op-only latencies).
        unsigned long long t0 = now_ns();
        int r = one_op();
        unsigned long long t1 = now_ns();
        if (i == busy_at && busy_ns > 0) {
            /* Controlled scheduling delay (P2fix6 NEW-31): spin
             * AFTER the op-only timing closes, so the NEXT op's
             * start lateness dominates deterministically. */
            unsigned long long spin_end = now_ns() + (unsigned long long)busy_ns;
            while (now_ns() < spin_end)
                ;
        }
        if (r == 0 || i == fail_at) {
            /* Failed-op lateness binds in the marker (P2fix5
             * NEW-31): the footer max folds this op's lateness, so
             * the receipt must carry it — otherwise a failed op
             * that sets the maximum orphans a real exit-6 into
             * timings-malformed. */
            fprintf(timings, "op_failed %ld %lld\n", i, late);
            unsigned long long fail_end = now_ns();
            fprintf(timings, "completed=%ld wall_ns=%llu max_late_ns=%lld origin_ns=%llu checksum=%ld\n",
                    completed, fail_end - start, max_late_ns, start, checksum);
            fclose(timings);
            printf("done completed=%ld FAILED_AT=%ld\n", completed, i);
            fflush(stdout);
            // The failed child still waits for X (P2fix2 item 26):
            // the seal takes live custody while the failure
            // receipt stands, then the child exits 6 (never 0 —
            // the failure is real on every wakeup, EOF included).
            ch = getchar();
            (void)ch;
            return 6;
        }
        checksum += r;
        completed++;
        fprintf(timings, "%llu %llu %lld %ld\n", t0, t1, late, i);
    }
    unsigned long long end = now_ns();
    fprintf(timings, "completed=%ld wall_ns=%llu max_late_ns=%lld origin_ns=%llu checksum=%ld\n",
            completed, end - start, max_late_ns, start, checksum);
    fclose(timings);
    printf("done completed=%ld checksum=%ld\n", completed, checksum);
    fflush(stdout);
    ch = getchar();
    return ch == 'X' ? 0 : 3;
}
