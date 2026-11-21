/* SPDX-License-Identifier: GPL-3.0-or-later
 * Phase 1 provider-load stimulus (fix2 NEW-P5, fix3 NEW-P5):
 * single-threaded explicit provider loads plus property-bearing
 * decoder/encoder fetches over a pipe handshake. Rounds are SPLIT
 * by kind ('L' = loads only: default x2, legacy x1; 'F' = fetches
 * only: decoder x2 with `input=der`, encoder x1 with
 * `output=text`; 'D' = digests only: 3 one-shot EVP_Digest calls
 * (fix4 seal-preservation pins — genuine BPF-counted operational
 * positives; standard legs never send it)) because one combined
 * round floods the ring: each
 * load fans out to whole provider-query dispatch tables, and the
 * combined burst drops newer edges (QueueLoss) — the L2 lesson
 * relearned (identical 2,1 ring-loss signature on every combined
 * run). Per-name totals are DISTINCT within each round (swapped
 * probes change the signature). Each done line reports all four
 * attempts,successes pairs (zeros for the idle kind) — the
 * independent oracle for the live legs. Loads rounds also report
 * the loaded provider HANDLES (`provd` = the two default handles,
 * `provl` = the legacy handle) and the startup line reports the
 * pre-load handles (`pre`), so the legs verify DISTINCT provider
 * identities (not just name classes) and prove the round's loads
 * are warm refcounts of the pre-loaded providers (cold module
 * arrival stays outside the narrowed claim). No observer code is
 * linked or injected. Property strings ride BOTH fetch kinds so
 * the legs prove the observer captures none of them; provider
 * name classes render as labels (never captured strings).
 * Operations are paced 500ms apart so the observer's concurrent
 * drains keep up with each operation's query fan-out.
 * `PROVIDER_LOAD_LOOP_NO_PRELOAD=1` skips the pre-loads
 * (diagnostic only: reproduces the cold first-legacy-load
 * observation poison — the standard legs never set it). */
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static const struct timespec PACE = { 0, 500 * 1000 * 1000 };

static void loads_round(void) {
    int default_ok = 0, legacy_ok = 0;
    OSSL_PROVIDER *d1 = NULL, *d2 = NULL, *l = NULL;
    {
        l = OSSL_PROVIDER_load(NULL, "legacy");
        if (l != NULL) {
            legacy_ok++;
        }
        nanosleep(&PACE, NULL);
    }
    d1 = OSSL_PROVIDER_load(NULL, "default");
    if (d1 != NULL) {
        default_ok++;
    }
    nanosleep(&PACE, NULL);
    d2 = OSSL_PROVIDER_load(NULL, "default");
    if (d2 != NULL) {
        default_ok++;
    }
    nanosleep(&PACE, NULL);
    printf("done default=%d,%d legacy=%d,%d dec=%d,%d enc=%d,%d provd=%p,%p provl=%p\n",
           2, default_ok, 1, legacy_ok, 0, 0, 0, 0,
           (void *)d1, (void *)d2, (void *)l);
}

/* NEW-6/NEW-13 fix4: genuine OPERATIONAL calls (one-shot
 * digests — counted in BPF per-cookie totals, never just ring
 * facts), so the seal-preservation pins observe real BPF-counted
 * positives. Paced like the other rounds; the done line is the
 * premise oracle (the workload ran). Standard legs never send
 * 'D'. */
static void digest_round(void) {
    int ok = 0;
    for (int i = 0; i < 3; i++) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        if (EVP_Digest("abc", 3, md, &len, EVP_sha256(), NULL)) {
            ok++;
        }
        nanosleep(&PACE, NULL);
    }
    printf("done digest=%d,%d\n", 3, ok);
}

static void fetches_round(void) {
    int dec_ok = 0, enc_ok = 0;
    for (int i = 0; i < 2; i++) {
        OSSL_DECODER *d = OSSL_DECODER_fetch(NULL, "RSA", "input=der");
        if (d != NULL) {
            dec_ok++;
            OSSL_DECODER_free(d);
        }
        nanosleep(&PACE, NULL);
    }
    {
        OSSL_ENCODER *e = OSSL_ENCODER_fetch(NULL, "RSA", "output=text");
        if (e != NULL) {
            enc_ok++;
            OSSL_ENCODER_free(e);
        }
        nanosleep(&PACE, NULL);
    }
    printf("done default=%d,%d legacy=%d,%d dec=%d,%d enc=%d,%d\n",
           0, 0, 0, 0, 2, dec_ok, 1, enc_ok);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* Pre-load both providers BEFORE the observer attaches: a
     * first legacy load mid-window pulls the legacy module and
     * the round goes totally silent afterwards (observed
     * deterministically in both orders — see the fix2 report).
     * Pre-loading moves module arrival before attach; the round's
     * explicit loads are still real observed calls (refcounted,
     * oracle-exact). The handles print on the `pre` line so the
     * legs prove the round's loads hit the SAME (warm) providers.
     * NO_PRELOAD=1 skips the pre-loads (cold-silence diagnostic
     * only — standard legs never set it). */
    OSSL_PROVIDER *pre_default = NULL, *pre_legacy = NULL;
    if (getenv("PROVIDER_LOAD_LOOP_NO_PRELOAD") == NULL) {
        pre_default = OSSL_PROVIDER_load(NULL, "default");
        pre_legacy = OSSL_PROVIDER_load(NULL, "legacy");
    }
    puts("ready");
    printf("pre default=%p legacy=%p\n", (void *)pre_default, (void *)pre_legacy);
    for (;;) {
        int c = getchar();
        if (c == 'X') {
            return 0;
        }
        if (c == 'L') {
            loads_round();
            continue;
        }
        if (c == 'F') {
            fetches_round();
            continue;
        }
        if (c == 'D') {
            digest_round();
            continue;
        }
        return 2;
    }
}
