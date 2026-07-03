/* abi_producer.c  --  the "library" side of an ABI boundary.
 *
 * This translation unit was updated to record layout v2: a 64-bit `value` and a
 * trailing `tag` were added. It is compiled and linked against a consumer that
 * still holds the v1 layout (see abi_confusion.c). Because C gives each TU its
 * own definition of `struct record`, the linker matches only the *symbol*
 * producer_fill -- never the *type*. The mismatch is therefore invisible at a
 * normal (non-LTO) build. That is the edge case this probe documents.
 */
#include <stdint.h>

/* v2 layout (current): kind@0, value@8 (64-bit), flags@16, tag@20 -> sizeof 24 */
struct record {
    uint32_t kind;
    uint64_t value;
    uint32_t flags;
    uint32_t tag;
};

void producer_fill(struct record *r) {
    r->kind  = 0x11111111u;
    r->value = 0xDEADBEEFCAFEF00Dull;
    r->flags = 0x33333333u;
    r->tag   = 0x44444444u;
}
