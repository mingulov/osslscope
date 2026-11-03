/* SPDX-License-Identifier: GPL-3.0-or-later
 * Control 3 adversarial third leg: logs arrival, then idles briefly so the
 * observer re-admits the second exec epoch before the process exits. */
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!OPENSSL_init_crypto(0, NULL)) return 3;
    FILE *log = fopen(argv[1], "a");
    if (!log) return 4;
    fprintf(log, "postexec2 %d\n", (int)getpid());
    fclose(log);
    sleep((unsigned)atoi(argv[2]));
    return 0;
}
