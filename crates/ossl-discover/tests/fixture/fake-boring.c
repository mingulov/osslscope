/* Fake BoringSSL-flavored libcrypto (P1 exit-5 doctor fixture):
 * BORINGSSL_-prefixed + EVP_ dynamic exports, no OpenSSL anchors
 * (no OSSL_provider_init, no OPENSSL_version_major) — the flavor
 * classifier must report BoringSSL and doctor must refuse (exit 4).
 * dlopened by map_sleeper (never fetched — not a provider). */
int BORINGSSL_fake_digest_init(void *ctx) {
    (void)ctx;
    return 1;
}

int BORINGSSL_fake_version(void) {
    return 0;
}

void *EVP_DigestInit(void) {
    return 0;
}
