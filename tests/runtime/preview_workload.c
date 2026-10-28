// SPDX-License-Identifier: GPL-3.0-or-later
// Finite EVP workload for the installed foreground preview, not a capture runner.
// Keys, IVs, ciphertext and tags remain in ephemeral process memory.
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

static const unsigned char message[] = "abc";
static const unsigned char sha256_abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

struct cipher_case {
    unsigned char key[32], iv[12], ciphertext[sizeof message - 1], tag[16];
};
struct work {
    unsigned long n;
    int sha, aes, ok;
    struct cipher_case *cases;
};

static int random_bytes(unsigned char *out, size_t n) {
    while (n) {
        ssize_t got = getrandom(out, n, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return 0;
        out += got;
        n -= (size_t)got;
    }
    return 1;
}

static int sha_loop(unsigned long n) {
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", "provider=default");
    if (!md) return 0;
    int ok = 1;
    for (unsigned long i = 0; i < n && ok; i++) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int size = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        ok = ctx && EVP_DigestInit_ex2(ctx, md, NULL) == 1
            && EVP_DigestUpdate(ctx, message, sizeof message - 1) == 1
            && EVP_DigestFinal_ex(ctx, digest, &size) == 1
            && size == sizeof sha256_abc
            && memcmp(digest, sha256_abc, sizeof sha256_abc) == 0;
        EVP_MD_CTX_free(ctx);
    }
    EVP_MD_free(md);
    return ok;
}

static int encrypt_loop(struct work *work) {
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", "provider=default");
    if (!cipher) return 0;
    int ok = 1;
    for (unsigned long i = 0; i < work->n && ok; i++) {
        struct cipher_case *c = &work->cases[i];
        unsigned char tail[EVP_MAX_BLOCK_LENGTH];
        int written = 0, final_size = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        ok = ctx && random_bytes(c->key, sizeof c->key)
            && random_bytes(c->iv, sizeof c->iv)
            && EVP_EncryptInit_ex2(ctx, cipher, c->key, c->iv, NULL) == 1
            && EVP_EncryptUpdate(ctx, c->ciphertext, &written, message, sizeof message - 1) == 1
            && written == (int)sizeof c->ciphertext
            && EVP_EncryptFinal_ex(ctx, tail, &final_size) == 1 && final_size == 0
            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof c->tag, c->tag) == 1;
        EVP_CIPHER_CTX_free(ctx);
    }
    EVP_CIPHER_free(cipher);
    return ok;
}

static void *perform(void *opaque) {
    struct work *work = opaque;
    work->ok = (!work->sha || sha_loop(work->n)) && (!work->aes || encrypt_loop(work));
    return NULL;
}

static int wait_success(pid_t child) {
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// Verify encryption by authenticated decryption in a separate thread group.
// Invoke only on the main thread after joining any worker. No key bytes cross
// a file or output channel, and verifier entries are outside the observed group.
static int verify_cipher(const struct work *work) {
    pid_t child = fork();
    if (child < 0) return 0;
    if (child != 0) return wait_success(child);
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", "provider=default");
    int ok = cipher != NULL;
    for (unsigned long i = 0; i < work->n && ok; i++) {
        const struct cipher_case *c = &work->cases[i];
        unsigned char plain[sizeof message - 1], tail[EVP_MAX_BLOCK_LENGTH];
        int size = 0, final_size = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        ok = ctx && EVP_DecryptInit_ex2(ctx, cipher, c->key, c->iv, NULL) == 1
            && EVP_DecryptUpdate(ctx, plain, &size, c->ciphertext, sizeof c->ciphertext) == 1
            && size == (int)sizeof plain
            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof c->tag, (void *)c->tag) == 1
            && EVP_DecryptFinal_ex(ctx, tail, &final_size) == 1 && final_size == 0
            && memcmp(plain, message, sizeof plain) == 0;
        EVP_CIPHER_CTX_free(ctx);
    }
    EVP_CIPHER_free(cipher);
    _exit(ok ? 0 : 1);
}

static int crypto_work(unsigned long n, int sha, int aes, int worker) {
    struct work work = { .n = n, .sha = sha, .aes = aes, .ok = 0, .cases = NULL };
    if (aes && !(work.cases = calloc(n, sizeof *work.cases))) return 0;
    if (worker) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, perform, &work) != 0) {
            free(work.cases);
            return 0;
        }
        if (pthread_join(thread, NULL) != 0) _exit(1);
    } else {
        perform(&work);
    }
    int ok = work.ok && (!aes || verify_cipher(&work));
    if (work.cases) {
        OPENSSL_cleanse(work.cases, n * sizeof *work.cases);
        free(work.cases);
    }
    return ok;
}

struct exec_work { char **argv; };
static void *exec_sha(void *opaque) {
    struct exec_work *work = opaque;
    execv(work->argv[0], work->argv);
    _exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) return 2;
    char *end = NULL;
    unsigned long n = argc == 3 ? strtoul(argv[2], &end, 10) : 32;
    if (!n || n > 100000 || (argc == 3 && (!*argv[2] || *end))) return 2;
    const char *mode = argv[1];
    if (!strcmp(mode, "exec") || !strcmp(mode, "worker-exec")) {
        char count[32];
        if (snprintf(count, sizeof count, "%lu", n) <= 0) return 1;
        char *next[] = { argv[0], "sha", count, NULL };
        struct exec_work work = { next };
        if (!strcmp(mode, "exec")) exec_sha(&work);
        pthread_t thread;
        if (pthread_create(&thread, NULL, exec_sha, &work) != 0) return 1;
        pthread_join(thread, NULL);
        return 1;
    }
    if (!strcmp(mode, "quiet")) {
        puts("READY quiet"); fflush(stdout);
        sleep(2);
        puts("OK quiet");
        return 0;
    }
    int warm = !strcmp(mode, "warm-sha");
    int sha = warm || !strcmp(mode, "sha") || !strcmp(mode, "sha-fail") || !strcmp(mode, "both")
        || !strcmp(mode, "worker") || !strcmp(mode, "forked") || !strcmp(mode, "mixed-fork");
    int aes = !strcmp(mode, "aes") || !strcmp(mode, "both")
        || !strcmp(mode, "worker") || !strcmp(mode, "forked") || !strcmp(mode, "mixed-fork");
    if (!sha && !aes) return 2;
    pid_t foreign = -1;
    if (!strcmp(mode, "forked") || !strcmp(mode, "mixed-fork")) {
        foreign = fork();
        if (foreign < 0) return 1;
        if (foreign == 0) _exit(crypto_work(n, 1, 1, 0) ? 0 : 1);
        if (!strcmp(mode, "forked")) {
            if (!wait_success(foreign)) return 1;
            printf("OK foreign-sha=%lu foreign-aes=%lu target=quiet\n", n, n);
            return 0;
        }
    }
    if (warm) {
        if (!crypto_work(1, 1, 0, 0)) return 1;
        puts("READY warm-sha"); fflush(stdout);
        if (getchar() != 'G') return 2;
    }
    int ok = crypto_work(n, sha, aes, !strcmp(mode, "worker"));
    if (warm) { puts("DONE warm-sha"); fflush(stdout); if (getchar() != 'E') return 2; }
    if (foreign > 0 && !wait_success(foreign)) ok = 0;
    if (!ok) { fputs("workload validation failed\n", stderr); return 1; }
    printf("OK sha=%lu aes=%lu foreign=%d\n", sha ? n : 0, aes ? n : 0, foreign > 0);
    return !strcmp(mode, "sha-fail") ? 7 : 0;
}
