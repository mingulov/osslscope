/* SPDX-License-Identifier: GPL-3.0-or-later */
/* P0-11 fallback fixture: ENGINE Y that shadows NID_sha256.
 * fallback_run(n): with FALLBACK_ENGINE=1 (default) registers the engine
 * and sets it default for digests, fetches SHA256 (X oracle), then runs n
 * init-only ops (EVP_DigestInit_ex + free). On 3.0 the init dispatches to
 * engine code while the fetch/EVP layer says X — the eCapture
 * counter-proof: EVP-level attribution (X) vs address-level (Y).
 * Init-only is principled, not a shortcut: 3.0's ENGINE default-digest
 * redirect is a half-removed legacy path — init executes engine code but
 * the ctx stays provider-bound (post-init md == fetched md, proven by
 * probe), so update/final cannot complete through it. The divergence at
 * init is genuine execution of Y under EVP identity X.
 * No-ENGINE builds (4.0+): stub reports unsupported (caller skips). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/opensslv.h>
/* 4.0+ removed the ENGINE API (engine.h may exist as a neutered stub,
 * so gate on the major version, not the header). */
#if OPENSSL_VERSION_MAJOR < 4
#include <openssl/engine.h>
#define HAVE_ENGINE 1
#else
#define HAVE_ENGINE 0
#endif
#include <openssl/evp.h>
#include <openssl/provider.h>

#if HAVE_ENGINE

static const char *ycounter_path(void)
{
    const char *p = getenv("FALLBACK_YCOUNTER");

    return (p != NULL && *p != '\0') ? p : "/tmp/spike/fallback-y.log";
}

static void ymark(const char *s)
{
    FILE *f = fopen(ycounter_path(), "a");

    if (f != NULL) {
        fprintf(f, "%s\n", s);
        fclose(f);
    }
}

__attribute__((noinline)) static int eng_init(EVP_MD_CTX *ctx)
{
    (void)ctx;
    ymark("Y:init");
    return 1;
}

/* Never reached through the 3.0 redirect (init-only divergence), but a
 * complete method in case some build dispatches further. */
__attribute__((noinline)) static int eng_update(EVP_MD_CTX *ctx,
    const void *data, size_t count)
{
    (void)ctx;
    (void)data;
    (void)count;
    ymark("Y:update");
    return 1;
}

__attribute__((noinline)) static int eng_final(EVP_MD_CTX *ctx,
    unsigned char *md)
{
    (void)ctx;
    memset(md, 0, 32);
    ymark("Y:final");
    return 1;
}

static EVP_MD *eng_sha256(void)
{
    EVP_MD *m = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption);

    if (m == NULL)
        return NULL;
    EVP_MD_meth_set_result_size(m, 32);
    EVP_MD_meth_set_input_blocksize(m, 64);
    EVP_MD_meth_set_app_datasize(m, 0);
    EVP_MD_meth_set_init(m, eng_init);
    EVP_MD_meth_set_update(m, eng_update);
    EVP_MD_meth_set_final(m, eng_final);
    return m;
}

static int eng_digests(ENGINE *e, const EVP_MD **digest, const int **nids,
    int nid)
{
    static int list[] = { NID_sha256, 0 };
    static EVP_MD *m = NULL;

    (void)e;
    if (digest == NULL) {
        *nids = list;
        return 1;
    }
    if (nid == NID_sha256) {
        if (m == NULL)
            m = eng_sha256();
        *digest = m;
        return *digest != NULL;
    }
    return 0;
}

/* n init-only ops. Prints X-provider/X-nid oracle + FALLBACK line.
 * Returns 0 ok, 1 op failure, 2 unsupported/register failure. */
int fallback_run(long n)
{
    ENGINE *e = NULL;
    EVP_MD *md;
    EVP_MD_CTX *ctx;
    const char *use_engine = getenv("FALLBACK_ENGINE");
    int want_engine = use_engine == NULL || *use_engine != '0';
    long i;

    remove(ycounter_path());
    if (want_engine) {
        e = ENGINE_new();
        if (e == NULL
            || !ENGINE_set_id(e, "fallback")
            || !ENGINE_set_name(e, "fallback")
            || !ENGINE_set_digests(e, eng_digests)
            || !ENGINE_add(e)
            || !ENGINE_set_default_digests(e)
            || !ENGINE_init(e)) {
            fprintf(stderr, "fallback: engine register failed\n");
            return 2;
        }
    }
    md = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (md == NULL) {
        fprintf(stderr, "fallback: fetch failed\n");
        return 2;
    }
    fprintf(stderr, "X-provider=%s X-nid=%d engine=%d\n",
        OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)),
        EVP_MD_get_type(md), want_engine);
    for (i = 0; i < n; i++) {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL)
            return 1;
        if (!EVP_DigestInit_ex(ctx, md, NULL)) {
            fprintf(stderr, "fallback: init %ld failed\n", i);
            EVP_MD_CTX_free(ctx);
            return 1;
        }
        EVP_MD_CTX_free(ctx);
    }
    fprintf(stderr, "FALLBACK ops=%ld\n", n);
    return 0;
}

#else /* !HAVE_ENGINE */

int fallback_run(long n)
{
    (void)n;
    fprintf(stderr, "FALLBACK=unsupported (no ENGINE API)\n");
    return 2;
}

#endif
