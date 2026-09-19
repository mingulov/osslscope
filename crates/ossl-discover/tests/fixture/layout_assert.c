/* SPDX-License-Identifier: GPL-3.0-or-later */
/* layout_assert.c — R12 fail-closed struct-shape + funcid-spot assertions.
 * Compiled against EACH lane's real OpenSSL headers (P1-0 lane pass):
 * any drift in a touched struct or transcribed id is a compile error.
 * Usage: gcc -I$OPENSSL/include -c layout_assert.c
 */
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <stddef.h>

/* --- Struct shapes (kinds.rs SHAPES; LP64) --- */
_Static_assert(sizeof(OSSL_DISPATCH) == 16, "OSSL_DISPATCH size");
_Static_assert(offsetof(OSSL_DISPATCH, function_id) == 0, "dispatch id off");
_Static_assert(offsetof(OSSL_DISPATCH, function) == 8, "dispatch fn off");

_Static_assert(sizeof(OSSL_ITEM) == 16, "OSSL_ITEM size");
_Static_assert(offsetof(OSSL_ITEM, id) == 0, "item id off");
_Static_assert(offsetof(OSSL_ITEM, ptr) == 8, "item ptr off");

_Static_assert(sizeof(OSSL_ALGORITHM) == 32, "OSSL_ALGORITHM size");
_Static_assert(offsetof(OSSL_ALGORITHM, algorithm_names) == 0, "alg names off");
_Static_assert(offsetof(OSSL_ALGORITHM, property_definition) == 8, "alg props off");
_Static_assert(offsetof(OSSL_ALGORITHM, implementation) == 16, "alg impl off");
_Static_assert(offsetof(OSSL_ALGORITHM, algorithm_description) == 24, "alg desc off");

_Static_assert(sizeof(OSSL_PARAM) == 40, "OSSL_PARAM size");
_Static_assert(offsetof(OSSL_PARAM, key) == 0, "param key off");
_Static_assert(offsetof(OSSL_PARAM, data_type) == 8, "param type off");
_Static_assert(offsetof(OSSL_PARAM, data) == 16, "param data off");
_Static_assert(offsetof(OSSL_PARAM, data_size) == 24, "param size off");
_Static_assert(offsetof(OSSL_PARAM, return_size) == 32, "param rsize off");

/* --- Op ids (kinds.rs OPS) --- */
_Static_assert(OSSL_OP_DIGEST == 1, "op digest");
_Static_assert(OSSL_OP_CIPHER == 2, "op cipher");
_Static_assert(OSSL_OP_MAC == 3, "op mac");
_Static_assert(OSSL_OP_KDF == 4, "op kdf");
_Static_assert(OSSL_OP_RAND == 5, "op rand");
_Static_assert(OSSL_OP_KEYMGMT == 10, "op keymgmt");
_Static_assert(OSSL_OP_KEYEXCH == 11, "op keyexch");
_Static_assert(OSSL_OP_SIGNATURE == 12, "op signature");
_Static_assert(OSSL_OP_ASYM_CIPHER == 13, "op asym cipher");
_Static_assert(OSSL_OP_KEM == 14, "op kem");
_Static_assert(OSSL_OP_ENCODER == 20, "op encoder");
_Static_assert(OSSL_OP_DECODER == 21, "op decoder");
_Static_assert(OSSL_OP_STORE == 22, "op store");
#ifdef OSSL_OP_SKEYMGMT
_Static_assert(OSSL_OP_SKEYMGMT == 15, "op skeymgmt");
#endif

/* --- Funcid spots incl. every since-boundary (kinds.rs FUNCS) --- */
_Static_assert(OSSL_FUNC_DIGEST_NEWCTX == 1, "digest newctx");
_Static_assert(OSSL_FUNC_DIGEST_INIT == 2, "digest init");
_Static_assert(OSSL_FUNC_PROVIDER_QUERY_OPERATION == 1027, "prov query");
_Static_assert(OSSL_FUNC_PROVIDER_UNQUERY_OPERATION == 1028, "prov unquery");
#ifdef OSSL_FUNC_DIGEST_SQUEEZE
_Static_assert(OSSL_FUNC_DIGEST_SQUEEZE == 14, "digest squeeze 3.5+");
#endif
#ifdef OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT
_Static_assert(OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT == 15, "cipher pipe 3.5+");
#endif
#ifdef OSSL_FUNC_SKEYMGMT_GENERATE
_Static_assert(OSSL_FUNC_SKEYMGMT_GENERATE == 4, "skeymgmt gen 3.5+");
#endif
#ifdef OSSL_FUNC_PROVIDER_RANDOM_BYTES
_Static_assert(OSSL_FUNC_PROVIDER_RANDOM_BYTES == 1032, "prov rand 3.5+");
#endif
#ifdef OSSL_FUNC_KDF_SET_SKEY
_Static_assert(OSSL_FUNC_KDF_SET_SKEY == 12, "kdf skey 3.6+");
_Static_assert(OSSL_FUNC_KDF_DERIVE_SKEY == 13, "kdf derive skey 3.6+");
#endif
#ifdef OSSL_FUNC_DIGEST_SERIALIZE
_Static_assert(OSSL_FUNC_DIGEST_SERIALIZE == 16, "digest ser 4.0+");
_Static_assert(OSSL_FUNC_DIGEST_DESERIALIZE == 17, "digest de 4.0+");
#endif
#ifdef OSSL_FUNC_KEYMGMT_NEW_EX
_Static_assert(OSSL_FUNC_KEYMGMT_NEW_EX == 17, "keymgmt new_ex 4.0+");
#endif

int main(void) { return 0; }
