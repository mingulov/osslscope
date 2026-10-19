// SPDX-License-Identifier: GPL-3.0-or-later
// count_flood: known-N OpenSSL digest driver for the count-rate
// live legs. Usage: count_flood <threads> <ops-per-thread> <pace-us> <mode>
// mode: sha256 (one hot digest) | mixed (even threads sha256, odd
// sha512: two hot keys) | many (cycle 8 digest names: medium-N drain).
// Prints: LEDGER offered=<ops> threads=<t> pace_us=<p> mode=<m>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static const char kMsg[64] = "osslscope count-rate known-N payload (fixed bytes, no secrets)";
static const char *kMany[8] = {
    "SHA256", "SHA512", "SHA384", "SHA224",
    "SHA512-256", "SHA3-256", "SHA3-512", "BLAKE2b512"
};
static const EVP_MD *kManyMd[8];
static const EVP_MD *kMdA;
static const EVP_MD *kMdB;
static long g_ops_per_thread;
static long g_pace_us;
static int g_mode; /* 0 sha256, 1 mixed, 2 many */
static void do_one(const EVP_MD *md) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outl = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fprintf(stderr, "FLOOD ctx-new failed\n"); exit(2); }
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1
        || EVP_DigestUpdate(ctx, kMsg, sizeof kMsg) != 1
        || EVP_DigestFinal_ex(ctx, out, &outl) != 1) {
        fprintf(stderr, "FLOOD digest failed\n"); exit(2);
    }
    EVP_MD_CTX_free(ctx);
}
static void *worker(void *arg) {
    intptr_t idx = (intptr_t)arg;
    for (long i = 0; i < g_ops_per_thread; i++) {
        if (g_mode == 0) {
            do_one(kMdA);
        } else if (g_mode == 1) {
            do_one((idx % 2 == 0) ? kMdA : kMdB);
        } else {
            do_one(kManyMd[(idx + i) % 8]);
        }
        if (g_pace_us > 0) { usleep((useconds_t)g_pace_us); }
    }
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <threads> <ops-per-thread> <pace-us> <sha256|mixed|many>\n", argv[0]);
        return 2;
    }
    long threads = atol(argv[1]);
    g_ops_per_thread = atol(argv[2]);
    g_pace_us = atol(argv[3]);
    if (strcmp(argv[4], "sha256") == 0) { g_mode = 0; }
    else if (strcmp(argv[4], "mixed") == 0) { g_mode = 1; }
    else if (strcmp(argv[4], "many") == 0) { g_mode = 2; }
    else { fprintf(stderr, "FLOOD bad mode\n"); return 2; }
    if (threads < 1 || threads > 64 || g_ops_per_thread < 1 || g_pace_us < 0) {
        fprintf(stderr, "FLOOD bad args\n"); return 2;
    }
    kMdA = EVP_get_digestbyname("SHA256");
    kMdB = EVP_get_digestbyname("SHA512");
    if (!kMdA || !kMdB) { fprintf(stderr, "FLOOD missing sha256/sha512\n"); return 2; }
    for (int i = 0; i < 8; i++) {
        kManyMd[i] = EVP_get_digestbyname(kMany[i]);
        if (!kManyMd[i]) { fprintf(stderr, "FLOOD missing %s\n", kMany[i]); return 2; }
    }
    pthread_t *t = calloc((size_t)threads, sizeof *t);
    if (!t) { fprintf(stderr, "FLOOD no mem\n"); return 2; }
    for (long i = 0; i < threads; i++) {
        if (pthread_create(&t[i], NULL, worker, (void *)(intptr_t)i) != 0) {
            fprintf(stderr, "FLOOD thread spawn failed\n"); return 2;
        }
    }
    for (long i = 0; i < threads; i++) { pthread_join(t[i], NULL); }
    printf("LEDGER offered=%ld threads=%ld pace_us=%ld mode=%s\n",
           threads * g_ops_per_thread, threads, g_pace_us, argv[4]);
    return 0;
}
