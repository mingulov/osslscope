/* SPDX-License-Identifier: GPL-3.0-or-later
 * 6D trace smoke stimulus: single-threaded fetch + one-shot digest loop
 * with a pipe handshake. No observer code is linked or injected. */
#include <openssl/evp.h>
#include <stdio.h>

int main(void) {
    static unsigned char input[64];
    static unsigned char out[64];
    for (int i = 0; i < 64; i++) {
        input[i] = (unsigned char)((unsigned)i * 2654435761u >> 24);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("ready");
    /* fix5 F3d: loop single G batches until X (G..done..G..done..X).
     * One-shot G..done..X still works exactly as before. */
    for (;;) {
        int c = getchar();
        if (c == 'X') {
            return 0;
        }
        if (c != 'G') {
            return 2;
        }
        int ok = 0;
        int fetched = 0;
        for (int i = 0; i < 60; i++) {
            EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
            if (md == NULL) {
                continue;
            }
            fetched++;
            size_t outlen = 0;
            if (EVP_Q_digest(NULL, "SHA2-256", NULL, input, sizeof input, out, &outlen) == 1
                && outlen == 32) {
                ok++;
            }
            EVP_MD_free(md);
        }
        printf("done ok=%d fetched=%d\n", ok, fetched);
    }
}
