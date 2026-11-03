/* SPDX-License-Identifier: GPL-3.0-or-later
 * Control-6 leg-B stimulus: N threads x tight EVP_DigestUpdate loop on the
 * default provider (real dispatch-table traversal, unlike direct fixture
 * callbacks which bypass the provider ring entirely). Sustained rate
 * overruns the 1MiB session ring (lane-0 LOSS). Links only the installed
 * libcrypto. argv: [threads, seconds]. Prints "ready <pid>", then "ops <N>". */
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static unsigned char buf[64];
static volatile unsigned long ops;

static void *spin(void *arg) {
    (void)arg;
    unsigned char out[64];
    unsigned int outl = 0;
    for (;;) {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        if (!c) return NULL;
        if (EVP_DigestInit_ex(c, EVP_sha512(), NULL) != 1) return NULL;
        for (int i = 0; i < 50; ++i)
            if (EVP_DigestUpdate(c, buf, sizeof buf) != 1) return NULL;
        if (EVP_DigestFinal_ex(c, out, &outl) != 1) return NULL;
        EVP_MD_CTX_free(c);
        __atomic_add_fetch(&ops, 50, __ATOMIC_RELAXED);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int n = atoi(argv[1]);
    int secs = atoi(argv[2]);
    if (n < 1 || n > 64 || secs < 1 || secs > 120) return 2;
    pthread_t *t = calloc((size_t)n, sizeof *t);
    if (!t) return 3;
    for (int i = 0; i < n; ++i)
        if (pthread_create(&t[i], NULL, spin, NULL) != 0) return 4;
    printf("ready %d\n", (int)getpid());
    fflush(stdout);
    sleep((unsigned)secs);
    printf("ops %lu\n", ops);
    return 0;
}
