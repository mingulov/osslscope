/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Real linker relocations and unwind records, with no OpenSSL dependency. */
#include <stdint.h>
struct dispatch { int id; void (*fn)(void); };
struct algorithm { const char *names, *properties; const struct dispatch *implementation; const char *description; };
#ifdef EXPORTED_IMPL
#define IMPL_VIS "protected"
#else
#define IMPL_VIS "hidden"
#endif
__attribute__((visibility(IMPL_VIS), noinline)) void implementation(void) {
    __asm__ volatile (".byte 0x0f,0x1f,0x44,0x00,0x00");
}
#ifdef LAYOUT_TWO
const unsigned char padding[317] = { 42 };
#define NAMES "FUTURE-KEM:UnfamiliarAlias"
#else
#define NAMES "NovelDigest:never-enrolled"
#endif
#ifdef UTF8_NAMES
#undef NAMES
#define NAMES "未来方式:未知別名"
#define DESCRIPTION "説明付きの実装"
#elif defined(BINARY_NAMES)
#undef NAMES
#define NAMES "\xff\xfe" "unrecognized:opaque"
#define DESCRIPTION "\x80" "opaque-description"
#else
#define DESCRIPTION "a description"
#endif
#ifdef NULL_NAME
#undef NAMES
#define NAMES 0
#endif
#ifdef EXTERNAL_ROW
extern void imported_function(void);
__asm__(".type imported_function,@function");
#define SECOND_FUNCTION imported_function
#else
#define SECOND_FUNCTION implementation
#endif
__attribute__((visibility("protected"))) const struct dispatch test_dispatch[] = {
    { 70001, implementation },
#ifndef ONE_ENTRY
    { 70002, SECOND_FUNCTION },
#endif
    { 0, 0 }
};
#ifdef OPAQUE_RECORDS
/* Public prefixes can be embedded in unrelated opaque containers. Their
 * suffix bytes are deliberately not a production layout contract. */
struct enclosing { struct algorithm public_record; uintptr_t opaque[3]; };
const struct enclosing test_algorithms[] = {
    { { NAMES, "provider=custom", test_dispatch, "description" }, { 17, 29, 41 } },
    { { "Different-Family:another-alias", 0, test_dispatch, 0 }, { 53, 67, 79 } }
};
#else
const struct algorithm test_algorithms[] = {
    { NAMES, "provider=custom", test_dispatch, DESCRIPTION },
    { "Different-Family:another-alias", 0, test_dispatch, 0 },
#ifdef EXTRA_SHARED
    { "Third-Family", 0, test_dispatch, 0 },
#endif
    { 0, 0, 0, 0 }
};
#endif
