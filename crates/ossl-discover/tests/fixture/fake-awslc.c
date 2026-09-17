/* Fake AWS-LC-flavored libcrypto (P1 exit-5 doctor fixture):
 * AWSLC_-prefixed + EVP_ dynamic exports, no OpenSSL anchors —
 * the flavor classifier must report AwsLc and doctor must refuse
 * (exit 4). dlopened by map_sleeper (never fetched). */
int AWSLC_fake_digest_init(void *ctx) {
    (void)ctx;
    return 1;
}

int AWSLC_fake_version(void) {
    return 0;
}

void *EVP_MD_CTX_new(void) {
    return 0;
}
