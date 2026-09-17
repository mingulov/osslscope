/* static_lowlevel.c — static-link blindness (P1 exit-3 static cell,
 * PLAN static-link cell). Low-level SHA256 linked against libcrypto.a
 * + stripped → no libcrypto mapping → inspect must emit
 * PARTIAL(anchor-unresolved) + the blind legacy section (full gaps,
 * mandated finding, engine_fallback_uninstrumented>0), never bare
 * "none". Build: gcc static_lowlevel.c $SSL/lib64/libcrypto.a -ldl
 * -pthread; strip. Gate asserts ldd shows no crypto + symtab empty.
 * Usage: static_lowlevel -n N (GO1: N SHA iters, GO2: idle, EOF: 0). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

static unsigned char input[1024];

static int run_sha(long n)
{
    SHA256_CTX c;
    unsigned char out[32];
    long i;

    for (i = 0; i < n; i++) {
        SHA256_Init(&c);
        SHA256_Update(&c, input, sizeof input);
        SHA256_Final(out, &c);
    }
    if (out[0] == 0 && out[31] == 0 && n > 0) {
        fprintf(stderr, "static_lowlevel: SHA256 zero (no-op call?)\n");
        return 1;
    }
    return 0;
}

static int want_go(const char *want)
{
    char line[16];

    if (fgets(line, sizeof line, stdin) == NULL)
        return -1;
    if (strcmp(line, "GO\n") != 0) {
        fprintf(stderr, "static_lowlevel: want %s\n", want);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    long n = -1;
    int i, rc;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atol(argv[++i]);
        } else {
            fprintf(stderr, "usage: static_lowlevel -n N\n");
            return 1;
        }
    }
    if (n < 0) {
        fprintf(stderr, "usage: static_lowlevel -n N\n");
        return 1;
    }
    memset(input, 0xA5, sizeof input);
    fprintf(stderr, "PID=%d\n", (int)getpid());
    rc = want_go("GO1");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    if (run_sha(n) != 0)
        return 1;
    fprintf(stderr, "SHADONE iters=%ld\n", n);
    rc = want_go("GO2");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    fprintf(stderr, "REFETCH2=ok\n");
    if (want_go("EOF") < 0)
        return 0;
    return 0;
}
