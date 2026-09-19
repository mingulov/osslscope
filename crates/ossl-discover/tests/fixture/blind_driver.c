/* SPDX-License-Identifier: GPL-3.0-or-later */
/* blind_driver.c — no-OpenSSL target for the P1 exit-3 blind cell.
 * Links only libc: no libcrypto mapping, so legacy tripwires cannot
 * attach and the doc must carry the blind legacy section (mandated
 * findings + full API-surface gaps), never a silent empty section.
 * Usage: blind_driver (GO1, GO2, EOF on stdin; exit 0). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int want_go(const char *want)
{
    char line[16];

    if (fgets(line, sizeof line, stdin) == NULL)
        return -1;
    if (strcmp(line, "GO\n") != 0) {
        fprintf(stderr, "blind_driver: want %s\n", want);
        return 1;
    }
    return 0;
}

int main(void)
{
    int rc;

    fprintf(stderr, "PID=%d\n", (int)getpid());
    rc = want_go("GO1");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    fprintf(stderr, "BLIND1=ok\n");
    rc = want_go("GO2");
    if (rc != 0)
        return rc < 0 ? 0 : 1;
    fprintf(stderr, "REFETCH2=ok\n");
    if (want_go("EOF") < 0)
        return 0;
    return 0;
}
