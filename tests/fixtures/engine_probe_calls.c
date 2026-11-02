/* SPDX-License-Identifier: GPL-3.0-or-later
 * Owned standalone ENGINE stimulus application with explicit stdin commands.
 * No observer code is linked or injected into this process. */
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

int main(int argc, char **argv) {
    if (argc != 1 && argc != 2) return 2;
    /* Optional finite-test command FIFO for held owned-startup controls. */
    if (argc == 2 && !freopen(argv[1], "r", stdin)) return 2;
    ENGINE_load_builtin_engines();
    puts("ready");
    fflush(stdout);
    int command, did = 0;
    while ((command = getchar()) != EOF && command != 'E') {
        int success = 0;
        if (command == '\n') continue;
        switch (command) {
        case 'B': {
            /* Exactly five dynamic-engine resolutions. */
            int n = 0;
            for (int i = 0; i < 5; i++) {
                ENGINE *e = ENGINE_by_id("dynamic");
                if (e) {
                    ENGINE_free(e);
                    n++;
                }
            }
            did += n;
            success = n == 5;
            break;
        }
        case 'F': {
            /* Failed resolution: must return NULL. */
            ENGINE *missing = ENGINE_by_id("osslscope-nonexistent-xyz");
            success = missing == NULL;
            if (missing) ENGINE_free(missing);
            break;
        }
        case 'M': {
            /* Map the next-line path as a retained private
               executable mapping: a new caller-set entry without
               dlopen (a dlopen produces the same maps event). */
            static void *kept[8];
            static int nkept = 0;
            int c;
            while ((c = getchar()) != '\n' && c != EOF) /* consume EOL */;
            char path[1024];
            if (nkept < 8 && fgets(path, sizeof path, stdin)) {
                path[strcspn(path, "\n")] = 0;
                FILE *f = fopen(path, "r");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long size = ftell(f);
                    void *p = MAP_FAILED;
                    if (size > 0)
                        p = mmap(NULL, (size_t)size, PROT_READ | PROT_EXEC,
                                 MAP_PRIVATE, fileno(f), 0);
                    fclose(f);
                    if (p != MAP_FAILED) {
                        kept[nkept++] = p;
                        success = 1;
                    }
                }
            }
            break;
        }
        default:
            break;
        }
        printf("ack %c %d did=%d\n", command, success, did);
        fflush(stdout);
    }
    printf("exit did=%d\n", did);
    return 0;
}
