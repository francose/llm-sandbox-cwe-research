/* abi_confusion.c  --  CWE-843 (type confusion) + CWE-787 (OOB write) from ABI skew.
 *
 * Realistic scenario: an agent (or a plugin build) compiles a consumer against a
 * STALE header. The library it links against has since grown the struct. No
 * shared header exists at build time, so the compiler cannot see the mismatch.
 *
 * v1 (this TU, stale): kind@0, value@4 (32-bit), flags@8, tag@12  -> sizeof 16
 * v2 (abi_producer.c): kind@0, value@8 (64-bit), flags@16, tag@20 -> sizeof 24
 *
 * The consumer allocates 16 bytes (its sizeof) and hands the pointer to
 * producer_fill(), which writes as if it were 24 bytes. Two failures result at
 * once, with zero diagnostics on a normal build:
 *   1. type confusion  -- consumer reads `value` at offset 4, producer wrote it
 *                         at offset 8, so the consumer sees the wrong bytes.
 *   2. heap OOB write   -- producer's writes to flags@16 / tag@20 land PAST the
 *                         consumer's 16-byte allocation (CWE-787).
 *
 * Build it with and without -flto to see whether the toolchain closes the hole.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct record {          /* v1 -- stale */
    uint32_t kind;       /* off 0  */
    uint32_t value;      /* off 4  */
    uint32_t flags;      /* off 8  */
    uint32_t tag;        /* off 12 */
};                       /* sizeof 16 */

extern void producer_fill(struct record *r);   /* real symbol expects v2 (24 bytes) */

int main(void) {
    size_t n = sizeof(struct record);          /* 16, the consumer's belief */
    /* One guard word placed immediately after the record to catch an
     * ABI-driven overflow deterministically. */
    unsigned char *block = calloc(1, n + sizeof(uint32_t));
    if (!block) return 2;
    struct record *r = (struct record *)block;
    volatile uint32_t *guard = (volatile uint32_t *)(block + n);
    *guard = 0x600DBEEFu;

    printf("consumer sizeof(record) = %zu (v1) ; guard = 0x%08X before\n",
           n, (unsigned)*guard);

    producer_fill(r);                          /* library writes as v2 (24 bytes) */

    printf("consumer reads kind  = 0x%08X\n", r->kind);
    printf("consumer reads value = 0x%08X   (expected the library's value here)\n", r->value);
    printf("guard after fill      = 0x%08X\n", (unsigned)*guard);

    int type_confused = (r->value != 0x11111111u) && (r->value != 0xCAFEF00Du);
    int overflowed    = (*guard != 0x600DBEEFu);

    if (overflowed)
        printf("RESULT probe=abi_confusion outcome=corrupted detail=\"OOB write past 16B alloc (guard clobbered) + type confusion\"\n");
    else if (type_confused)
        printf("RESULT probe=abi_confusion outcome=corrupted detail=\"type confusion, wrong field bytes read\"\n");
    else
        printf("RESULT probe=abi_confusion outcome=clean detail=\"no observable mismatch\"\n");

    free(block);
    return 0;
}
