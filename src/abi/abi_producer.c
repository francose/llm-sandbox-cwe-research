/*
 * abi_producer.c -- the library side of the ABI mismatch.
 *
 * This is the newer layout: a 64-bit `value` and a `tag` were added, so the struct is
 * now 24 bytes. It gets linked against abi_confusion.c, which still uses the old
 * 16-byte layout. C lets each file keep its own definition of `struct record`, so the
 * linker only matches the name producer_fill, not the type -- which is why a normal
 * build never warns.
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
