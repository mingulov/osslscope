/* SPDX-License-Identifier: GPL-3.0-or-later
 * Phase 1 fetch-surface stimulus: single-threaded fetch + free loop over
 * the eight P1-A1 extension surfaces with a pipe handshake. Per-surface
 * attempt AND outcome totals are DISTINCT (swapped probes or a broken
 * classifier cannot hide behind uniform counts), and every surface makes
 * real NULL-returning calls (bogus names the provider cannot resolve) so
 * an always-success classifier is detected. The done line reports
 * per-surface attempts,successes (the independent oracle for the live
 * leg). No observer code is linked or injected. Fetch-only: no
 * digest/cipher calls, so OpenSSL issues no incidental nested fetches
 * of its own (any extra attempt edge is a genuine observation the leg
 * must explain, never noise to subtract). Encoder/decoder calls carry
 * property strings on BOTH succeeding and failing calls, proving the
 * observer captures none of them either way. */
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <stdio.h>
#include <time.h>

/* Distinct per-surface totals (fix1 NEW-P6): attempts 8..1, exactly
 * one bogus (NULL-returning) call per surface, successes 7..0 — the
 * attempt and success vectors are pairwise distinct across surfaces
 * (swapped probes change the signature; the per-surface NULL return
 * defeats an always-success classifier). The 36-call burst stays below
 * the 64-call burst the lane proved lossless: every fetch fans out to
 * Each surface's first queries (one real + one bogus name) fan out to
 * hundreds of provider-query dispatch facts each — 16 unique queries
 * roughly double the 8-query flood the lane proved lossless — and an
 * unpaced burst overruns the ring and drops newer fetch edges
 * (QueueLoss). Surfaces are therefore paced 400ms apart (the L1 smoke
 * pattern, widened): the leg proves per-surface observation, not ring
 * capacity. */
#define N_SURFACES 8
static const int ATTEMPTS[N_SURFACES] = { 8, 7, 6, 5, 4, 3, 2, 1 };
static const int BOGUS[N_SURFACES] = { 1, 1, 1, 1, 1, 1, 1, 1 };
static const struct timespec PACE = { 0, 400 * 1000 * 1000 };

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ready");
    for (;;) {
        int c = getchar();
        if (c == 'X') {
            return 0;
        }
        if (c != 'G') {
            return 2;
        }
        int ok[N_SURFACES] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        for (int i = 0; i < N_SURFACES; i++) {
            for (int j = 0; j < ATTEMPTS[i]; j++) {
                int bogus = (j < BOGUS[i]);
                switch (i) {
                case 0: {
                    EVP_ASYM_CIPHER *a = EVP_ASYM_CIPHER_fetch(
                        NULL, bogus ? "BOGUS-ASYM-ALG" : "RSA", NULL);
                    if (a != NULL) {
                        ok[i]++;
                        EVP_ASYM_CIPHER_free(a);
                    }
                    break;
                }
                case 1: {
                    EVP_KEYEXCH *k = EVP_KEYEXCH_fetch(
                        NULL, bogus ? "BOGUS-KEXCH-ALG" : "DH", NULL);
                    if (k != NULL) {
                        ok[i]++;
                        EVP_KEYEXCH_free(k);
                    }
                    break;
                }
                case 2: {
                    EVP_KEYMGMT *m = EVP_KEYMGMT_fetch(
                        NULL, bogus ? "BOGUS-KMGMT-ALG" : "RSA", NULL);
                    if (m != NULL) {
                        ok[i]++;
                        EVP_KEYMGMT_free(m);
                    }
                    break;
                }
                case 3: {
                    EVP_RAND *r = EVP_RAND_fetch(
                        NULL, bogus ? "BOGUS-RAND-ALG" : "CTR-DRBG", NULL);
                    if (r != NULL) {
                        ok[i]++;
                        EVP_RAND_free(r);
                    }
                    break;
                }
                case 4: {
                    EVP_SKEYMGMT *s = EVP_SKEYMGMT_fetch(
                        NULL, bogus ? "BOGUS-SKEY-ALG" : "AES", NULL);
                    if (s != NULL) {
                        ok[i]++;
                        EVP_SKEYMGMT_free(s);
                    }
                    break;
                }
                case 5: {
                    OSSL_DECODER *d = OSSL_DECODER_fetch(
                        NULL, bogus ? "BOGUS-DEC-ALG" : "RSA", "input=der");
                    if (d != NULL) {
                        ok[i]++;
                        OSSL_DECODER_free(d);
                    }
                    break;
                }
                case 6: {
                    OSSL_ENCODER *e = OSSL_ENCODER_fetch(
                        NULL, bogus ? "BOGUS-ENC-ALG" : "RSA", "output=text");
                    if (e != NULL) {
                        ok[i]++;
                        OSSL_ENCODER_free(e);
                    }
                    break;
                }
                case 7: {
                    OSSL_STORE_LOADER *t = OSSL_STORE_LOADER_fetch(
                        NULL, bogus ? "bogus-scheme-xyz" : "file", NULL);
                    if (t != NULL) {
                        ok[i]++;
                        OSSL_STORE_LOADER_free(t);
                    }
                    break;
                }
                }
            }
            /* Pace surfaces apart so the observer's concurrent drains
             * keep up with each surface's query fan-out (see above). */
            nanosleep(&PACE, NULL);
        }
        printf("done asym=%d,%d kexch=%d,%d kmgmt=%d,%d rand=%d,%d skey=%d,%d dec=%d,%d "
               "enc=%d,%d store=%d,%d\n",
               ATTEMPTS[0], ok[0], ATTEMPTS[1], ok[1], ATTEMPTS[2], ok[2], ATTEMPTS[3], ok[3],
               ATTEMPTS[4], ok[4], ATTEMPTS[5], ok[5], ATTEMPTS[6], ok[6], ATTEMPTS[7], ok[7]);
    }
}
