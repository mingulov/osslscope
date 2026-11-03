/* SPDX-License-Identifier: GPL-3.0-or-later
 * Control 9c stimulus: unshare the mount namespace mid-observation.
 * argv: [logpath, gopath, hold_secs]. Links libcrypto (eligible member).
 * Logs mount-ns ids before/after (oracle: incarnation change). */
#define _GNU_SOURCE
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/stat.h>

static int wait_go(const char *path) {
    for (int i = 0; i < 600; ++i) {
        if (access(path, F_OK) == 0) return 1;
        struct timespec tenth = { 0, 100000000L };
        nanosleep(&tenth, NULL);
    }
    return 0;
}
static unsigned long long ns_id(const char *which) {
    char path[64], link[64];
    snprintf(path, sizeof(path), "/proc/self/ns/%s", which);
    ssize_t n = readlink(path, link, sizeof(link) - 1);
    if (n <= 0) return 0;
    link[n] = '\0';
    unsigned long long ino = 0;
    sscanf(link, "%*[a-z]:[%llu]", &ino);
    return ino;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    const char *logpath = argv[1], *gopath = argv[2];
    int hold = atoi(argv[3]);
    if (hold < 1 || hold > 120) return 2;
    if (!OPENSSL_init_crypto(0, NULL)) return 3;
    FILE *log = fopen(logpath, "w");
    if (!log) return 4;
    setvbuf(log, NULL, _IONBF, 0);
    fprintf(log, "ready %d mnt=%llu pidns=%llu\n",
            (int)getpid(), ns_id("mnt"), ns_id("pid"));
    if (!wait_go(gopath)) { fprintf(log, "go_timeout\n"); fclose(log); return 5; }
    if (unshare(CLONE_NEWNS) != 0) { fprintf(log, "unshare_failed\n"); fclose(log); return 6; }
    fprintf(log, "unshared mnt=%llu pidns=%llu\n", ns_id("mnt"), ns_id("pid"));
    sleep((unsigned)hold);
    fprintf(log, "done\n");
    fclose(log);
    return 0;
}
