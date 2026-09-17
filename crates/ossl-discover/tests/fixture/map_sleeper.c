/* map_sleeper (P1 exit-5 doctor fixture): dlopen every argv entry,
 * print PID= + MAPOK=n, sleep 60. No GO protocol, no fetch —
 * doctor inspects the mappings directly. Multiple paths exercise
 * the dual-load detector. Exit 2 when any mapping fails. */
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: map_sleeper <so-path>...\n");
        return 2;
    }
    printf("PID=%d\n", (int)getpid());
    fflush(stdout);
    for (int i = 1; i < argc; i++) {
        if (!dlopen(argv[i], RTLD_NOW)) {
            fprintf(stderr, "map_sleeper: dlopen failed: %s: %s\n", argv[i], dlerror());
            return 2;
        }
    }
    printf("MAPOK=%d\n", argc - 1);
    fflush(stdout);
    sleep(60);
    return 0;
}
