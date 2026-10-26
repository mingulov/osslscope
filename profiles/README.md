<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Preview callback catalogue

This built-in data establishes static enrollment. Separate native checks of the
foreground preview cover the [advertised profile](../docs/release-v0.2.0.md);
the catalogue itself grants no broader runtime support.

The current catalogue matches Ubuntu OpenSSL `3.5.5-1ubuntu3.7`, amd64, using
exact library SHA-256/GNU build ID and matching debug symbols. Kernel release
and GNU build identity are also pinned. Runtime admission accepts no external
catalogue or guessed offsets.

| File offset | Callback entry | Compiled candidate meaning |
| --- | --- | --- |
| `0x411950` | `sha256_newctx` | SHA-256 context creation |
| `0x3fe700` | `aes256gcm_newctx` | AES-256-GCM context creation |
| `0x472bc0` | `ossl_gcm_stream_update` | Shared AES/ARIA/SM4 GCM update, seven candidates |

Each entry was matched to its executable file range, matching debug symbol,
actual dispatch row and ELF pointer relocation. The complete compiled alias
strings were classified with the existing finite algorithm registry; canonical
OID classes are intentional. The shared update remains one physical site and
has no definite individual algorithm classification. Counts do not prove
message processing, success, key size or runtime provider activation.

The matching Ubuntu source package is available from the official archive:
`https://archive.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_3.5.5-1ubuntu3.7.dsc`.
Its original source archive SHA-256 is
`b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89`;
Debian/Ubuntu patch archive SHA-256 is
`b9c389484ff47a3b1f584eb89c7442484df9295aa48e6e422243dd559b89c089`.
Source ties include `sha2_prov.c`/`digestcommon.h`, `cipher_aes_gcm.c`/
`ciphercommon_aead.h`, and the corresponding ARIA/SM4 GCM tables. Catalogue
updates require the same membership/alias review and actual release qualification.
