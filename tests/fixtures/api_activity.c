// SPDX-License-Identifier: GPL-3.0-or-later
// Ordinary public OpenSSL APIs. Data/keys/outputs are never observer inputs.
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>
#include <stdio.h>
#define OK(x) do { if ((x) != 1) return __LINE__; } while (0)
int main(int argc, char **argv) {
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
    if (!md) return 2;
    if (argc > 1 && !strcmp(argv[1], "unused")) { EVP_MD_free(md); return 0; }
    unsigned char data[] = "PRIVATE_API_PAYLOAD_CANARY";
    unsigned char key[32] = {0}, iv[16] = {0}, output[256], encrypted[256];
    unsigned int mdlen; int n, extra; size_t len;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    OK(EVP_DigestInit_ex2(m, md, NULL)); OK(EVP_DigestUpdate(m, data, sizeof(data))); OK(EVP_DigestFinal_ex(m, output, &mdlen));
    EVP_MD_CTX_free(m); EVP_MD_free(md);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    OK(EVP_EncryptInit_ex2(c, EVP_aes_256_gcm(), key, iv, NULL));
    OK(EVP_EncryptUpdate(c, encrypted, &n, data, sizeof(data))); OK(EVP_EncryptFinal_ex(c, encrypted+n, &extra));
    EVP_CIPHER_CTX_free(c);
    c = EVP_CIPHER_CTX_new(); OK(EVP_DecryptInit_ex2(c, EVP_aes_256_gcm(), key, iv, NULL));
    OK(EVP_DecryptUpdate(c, output, &n, encrypted, sizeof(data)));
    if (EVP_DecryptFinal_ex(c, output+n, &extra) != 0) return 3; // Missing tag.
    EVP_CIPHER_CTX_free(c);
    c = EVP_CIPHER_CTX_new(); OK(EVP_CipherInit_ex(c, EVP_aes_256_ctr(), NULL, key, iv, 1));
    OK(EVP_CipherUpdate(c, output, &n, data, sizeof(data))); OK(EVP_CipherFinal_ex(c, output+n, &extra)); EVP_CIPHER_CTX_free(c);
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL); if (!mac) return 4;
    EVP_MAC_CTX *mc = EVP_MAC_CTX_new(mac);
    OSSL_PARAM mp[] = { OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA512", 0), OSSL_PARAM_END };
    OK(EVP_MAC_init(mc, key, sizeof(key), mp)); OK(EVP_MAC_update(mc, data, sizeof(data))); OK(EVP_MAC_final(mc, output, &len, sizeof(output))); EVP_MAC_CTX_free(mc); EVP_MAC_free(mac);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL); if (!kdf) return 5;
    EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM kp[] = { OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0), OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)), OSSL_PARAM_END };
    OK(EVP_KDF_derive(kc, output, 32, kp)); EVP_KDF_CTX_free(kc);
    kc = EVP_KDF_CTX_new(kdf); if (EVP_KDF_derive(kc, output, 32, NULL) != 0) return 6; EVP_KDF_CTX_free(kc); EVP_KDF_free(kdf);
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"); if (!pkey) return 7;
    unsigned char sig[128]; size_t siglen = sizeof(sig);
    m = EVP_MD_CTX_new(); OK(EVP_DigestSignInit(m, NULL, NULL, NULL, pkey));
    OK(EVP_DigestSign(m, NULL, &siglen, data, sizeof(data))); // Successful size query is still one API return.
    OK(EVP_DigestSign(m, sig, &siglen, data, sizeof(data))); EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new(); OK(EVP_DigestVerifyInit(m, NULL, NULL, NULL, pkey));
    OK(EVP_DigestVerify(m, sig, siglen, data, sizeof(data))); sig[0] ^= 1;
    if (EVP_DigestVerify(m, sig, siglen, data, sizeof(data)) != 0) return 8;
    EVP_MD_CTX_free(m); EVP_PKEY_free(pkey);
    OK(EVP_RAND_generate(RAND_get0_public(NULL), output, 32, 128, 0, NULL, 0));
    if (EVP_RAND_generate(RAND_get0_public(NULL), output, 32, 999999, 0, NULL, 0) != 0) return 9;
    puts("six families complete"); return 0;
}
