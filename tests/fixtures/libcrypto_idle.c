/* SPDX-License-Identifier: GPL-3.0-or-later
 * NEW-17 fix5: libcrypto-mapped idle child (no stdin, no stdout
 * handshake, no crypto calls — zero ring pressure). Blocks in
 * pause() until killed; the observer pins terminal-custody seals
 * against it without loss/latch masking. Killed by the test
 * (kill_test_child) or SIGTERM; never exits on its own. */
#include <openssl/crypto.h>
#include <signal.h>
#include <unistd.h>

static void on_term(int sig)
{
    (void)sig;
    _exit(0);
}

int main(void)
{
    /* Reference libcrypto so the mapping is real and retained. */
    if (OpenSSL_version_num() == 0) {
        return 2;
    }
    struct sigaction sa;
    sa.sa_handler = on_term;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    for (;;) {
        pause();
    }
}
