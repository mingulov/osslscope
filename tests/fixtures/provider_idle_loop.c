/* SPDX-License-Identifier: GPL-3.0-or-later
 * Phase 1 genuine-idle stimulus (fix10 FLAG-C): pre-loads both
 * providers (warming the exact surfaces the observer attaches),
 * prints `ready`, then sleeps forever WITHOUT further crypto —
 * the observed window is genuinely idle (zero BPF-counted
 * activity), unlike `openssl speed` (always working) or the
 * load loop (idle only until driven over a pipe the adopt flow
 * cannot hold). No observer code is linked or injected. The
 * parent kills it (default SIGTERM disposition). Stdout carries
 * the ready line (the pin polls it through a file sink); stdin
 * is never read.
 * NEW-37 fix11: readiness requires BOTH provider handles — a
 * failed load never prints `ready` (fail closed, nonzero exit).
 * `OSSLSCOPE_IDLE_DROP_LEGACY` (test-only) swaps the legacy load
 * for a nonexistent provider so the real NULL path is pinnable. */
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *legacy = "legacy";
    if (getenv("OSSLSCOPE_IDLE_DROP_LEGACY") != NULL) {
        legacy = "osslscope-nonexistent-provider";
    }
    OSSL_PROVIDER *d = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *l = OSSL_PROVIDER_load(NULL, legacy);
    if (d == NULL || l == NULL) {
        puts("provider-load-failed");
        return 1;
    }
    puts("ready");
    for (;;) {
        sleep(3600);
    }
    return 0;
}
