/* SPDX-License-Identifier: GPL-3.0-or-later
 * Phase 1 NEW-48 stimulus (fix15): linked against BOTH staged
 * libcrypto and a staged test provider module (DT_NEEDED on both,
 * so pre-exec discovery prearms API sites on TWO distinct backing
 * files under one PID), then digests forever at a gentle pace
 * (genuine BPF-counted operational positives) until the parent
 * kills it (default SIGTERM disposition, like the idle fixture).
 * The `fixture_count_reset` call keeps the provider DT_NEEDED
 * entry (else the linker drops the unreferenced dependency).
 * Prints `ready` first. No observer code is linked or injected.
 * Stdout carries the ready line; stdin is never read. */
#include <openssl/evp.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

extern void fixture_count_reset(void);

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    fixture_count_reset();
    puts("ready");
    static const unsigned char msg[64] = {
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    };
    unsigned char md[64];
    unsigned int len = 0;
    static const struct timespec PACE = { 0, 5 * 1000 * 1000 };
    for (;;) {
        if (!EVP_Digest(msg, sizeof msg, md, &len, EVP_sha256(), NULL)) {
            puts("digest-failed");
            return 1;
        }
        nanosleep(&PACE, NULL);
    }
    return 0;
}
