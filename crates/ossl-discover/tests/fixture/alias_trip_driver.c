/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Alias-trip driver (T02 live privacy gate): every decoded
 * ENGINE/load argument pointer aliases a DISTINCT secret sentinel.
 * On GO the driver fires OSSL_PROVIDER_load with a short and an
 * overlong sentinel name plus ENGINE_by_id with a third sentinel
 * (3.x only; 4.x removed ENGINE):
 *   load short:  T02ALIAS-LOAD-SHORT-03
 *   load long:   T02ALIAS-LOAD-LONG-04- + 'L' fill (200 chars: overlong)
 *   engine id:   T02ALIAS-ENGINE-05
 * All three lookups must FAIL (unknown names) while the entry
 * probes fire regardless — the tripwire doctrine. Live-gate
 * procedure (needs the approved lane + T05 harness; NOT run in
 * T02): observe this driver with --legacy, then assert (a) zero
 * bytes of any sentinel in inspect/report/check/CBOM/stdout/stderr,
 * live rings, and every inventoried map, and (b) the positive
 * control: `other` load/engine-id classes for the short args plus
 * unreadable/overlong evidence for the long arg.
 * Usage: alias_trip_driver (GO on stdin, ALIASDONE on stderr, EOF
 * on stdin; exit 0; exit 2 if any lane unexpectedly succeeds). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#if OPENSSL_VERSION_MAJOR < 4
#include <openssl/engine.h>
#endif

#define S_LOAD_SHORT "T02ALIAS-LOAD-SHORT-03"
#define S_LOAD_LONG_PFX "T02ALIAS-LOAD-LONG-04-"
#define S_ENGINE_ID "T02ALIAS-ENGINE-05"

static int fails;

#define LANE_OK(n) do { fprintf(stderr, "LANE %s ok\n", n); } while (0)
#define LANE_FAIL(n) do { fprintf(stderr, "LANE %s FAIL\n", n); fails++; } while (0)
#define LANE_SKIP(n, w) do { fprintf(stderr, "LANE %s skip:%s\n", n, w); } while (0)

/* Provider-load alias lanes: short + overlong sentinel names. */
static void lane_load(void)
{
    char longname[201];
    OSSL_PROVIDER *p;

    p = OSSL_PROVIDER_load(NULL, S_LOAD_SHORT);
    if (p != NULL)
        OSSL_PROVIDER_unload(p);
    memset(longname, 'L', sizeof longname - 1);
    longname[sizeof longname - 1] = '\0';
    memcpy(longname, S_LOAD_LONG_PFX, sizeof S_LOAD_LONG_PFX - 1);
    {
        OSSL_PROVIDER *q = OSSL_PROVIDER_load(NULL, longname);

        if (q != NULL)
            OSSL_PROVIDER_unload(q);
        /* Both must FAIL lookup (unknown names) — the entry probes
         * still fired. */
        if (p == NULL && q == NULL)
            LANE_OK("load");
        else
            LANE_FAIL("load");
    }
}

/* ENGINE_by_id alias lane (3.x only). */
static void lane_engine(void)
{
#if OPENSSL_VERSION_MAJOR >= 4
    LANE_SKIP("engine", "no-ENGINE");
#else
    ENGINE *e = ENGINE_by_id(S_ENGINE_ID);

    if (e != NULL)
        ENGINE_free(e);
    /* Unknown id must fail — the entry probe still fired. */
    if (e == NULL)
        LANE_OK("engine");
    else
        LANE_FAIL("engine");
#endif
}

int main(void)
{
    char line[64];

    fprintf(stderr, "PID=%d\n", (int)getpid());
    if (fgets(line, sizeof line, stdin) == NULL)
        return 0;
    if (strncmp(line, "GO", 2) != 0) {
        fprintf(stderr, "alias_trip_driver: want GO\n");
        return 1;
    }
    lane_load();
    lane_engine();
    fprintf(stderr, "ALIASDONE fails=%d\n", fails);
    if (fgets(line, sizeof line, stdin) == NULL)
        return 0;
    return fails != 0 ? 2 : 0;
}
