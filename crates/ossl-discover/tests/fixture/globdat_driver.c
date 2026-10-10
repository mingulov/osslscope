/* SPDX-License-Identifier: GPL-3.0-or-later */
/* T09 GLOB_DAT driver: mirrors libssl's address-taken low-level
 * imports (the four digest Transform routines, R_X86_64_GLOB_DAT,
 * no PLT stub). Takes each address into a volatile slot and calls
 * it exactly once through the pointer over zero blocks, so the
 * binary carries four code GLOB_DAT relocs AND executes through
 * them. The C4 oracle: the observer reports the four precise
 * `address-taken import` findings with libcrypto resolution, keeps
 * `lowlevel-fallback-uninstrumented`, and never claims the pointer
 * calls as counted tripwire execution.
 *
 * Usage: globdat_driver
 * stdout: LEDGER + GLOBDONE. stderr: diagnostics. Exit 2 on failure.
 * Build: gcc -O1 -o globdat_driver globdat_driver.c -lcrypto
 * (volatile slots defeat DCE without -O0; verify with
 * `readelf -rW globdat_driver | grep GLOB_DAT`.)
 */
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

typedef void (*transform_fn)(void *, const unsigned char *);

/* Volatile: the addresses must materialize as GLOB_DAT slots, and
 * the calls must go through the loaded pointers (a direct call
 * would take the PLT and void the fixture). */
static volatile transform_fn slot_md5;
static volatile transform_fn slot_sha1;
static volatile transform_fn slot_sha256;
static volatile transform_fn slot_sha512;

int main(void)
{
    MD5_CTX m5;
    SHA_CTX s1;
    SHA256_CTX s256;
    SHA512_CTX s512;
    unsigned char block[128];
    int taken = 0, calls = 0;

    memset(&m5, 0, sizeof m5);
    memset(&s1, 0, sizeof s1);
    memset(&s256, 0, sizeof s256);
    memset(&s512, 0, sizeof s512);
    memset(block, 0, sizeof block);

    slot_md5 = (transform_fn)MD5_Transform;
    slot_sha1 = (transform_fn)SHA1_Transform;
    slot_sha256 = (transform_fn)SHA256_Transform;
    slot_sha512 = (transform_fn)SHA512_Transform;
    taken = (slot_md5 != NULL) + (slot_sha1 != NULL)
        + (slot_sha256 != NULL) + (slot_sha512 != NULL);
    if (taken != 4) {
        fprintf(stderr, "globdat_driver: short address-taken set\n");
        return 2;
    }
    /* One call each through the pointer (zero state/block: the
     * fixture proves the call path, not digest values). */
    slot_md5(&m5, block);
    slot_sha1(&s1, block);
    slot_sha256(&s256, block);
    slot_sha512(&s512, block);
    calls = 4;

    printf("LEDGER op=globdat pointers_taken=%d ptr_calls=%d\n", taken, calls);
    printf("GLOBDONE rc=0\n");
    return 0;
}
