/*
 * abi_confusion.c -- CWE-843 and CWE-787 caused by an ABI mismatch.
 *
 * The case I care about: someone builds against an old copy of a header while the
 * library it links against has moved on and made the struct bigger. Nothing shares
 * the header at build time, so the compiler never sees the two sides disagree.
 *
 * Here the stale struct is 16 bytes and the library's is 24. This file allocates 16
 * bytes and hands the pointer to producer_fill(), which writes 24 bytes worth. Two
 * things go wrong at once and neither shows up on a normal build: it reads `value`
 * from the wrong offset (type confusion), and it writes past the 16-byte allocation
 * (a heap overflow). Try it with and without -flto to see if the toolchain notices.
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
