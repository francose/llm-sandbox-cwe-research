/*
 * oob_write.c -- CWE-787, showing which defense catches which kind of overflow.
 *
 * Three cases, picked so the flag matrix shows where each defense fires and, more to
 * the point, where it doesn't:
 *   intra  overflow one field into the next field of the same allocation. It stays
 *          inside the malloc'd object, so AddressSanitizer never sees it, and this one
 *          gets through everything.
 *   heap   write past the end of the allocation. AddressSanitizer catches this; the
 *          others don't.
 *   stack  memcpy too much into a fixed stack buffer. The stack canary and FORTIFY
 *          catch this, which is the point: the stack is defended by default, the heap
 *          is not.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void variant_intra(void) {
    struct box { char buf[8]; unsigned long canary; };
    struct box *b = calloc(1, sizeof *b);
    if (!b) return;
    b->canary = 0x0123456789ABCDEFull;
    for (size_t i = 0; i < sizeof b->buf + 8; i++)  /* buf[8] + into canary */
        ((volatile char *)b->buf)[i] = 'A';
    int corrupt = b->canary != 0x0123456789ABCDEFull;
    printf("intra: canary=0x%016lX\n", b->canary);
    printf("RESULT probe=oob_write variant=intra outcome=%s detail=\"field-to-field overflow within one allocation; ASan-invisible\"\n",
           corrupt ? "corrupted" : "clean");
    free(b);
}

static void variant_heap(void) {
    volatile char *p = malloc(8);
    if (!p) return;
    for (size_t i = 0; i < 16; i++)                 /* 8 bytes past an 8-byte alloc */
        p[i] = 'A';
    printf("RESULT probe=oob_write variant=heap outcome=corrupted detail=\"8B written past 8B allocation; silent unless ASan traps it\"\n");
    free((void *)p);
}

static void variant_stack(void) {
    char buf[8];
    char src[64];
    memset(src, 'A', sizeof src);
    volatile size_t len = 40;                        /* runtime len -> forces __memcpy_chk */
    memcpy(buf, src, len);                            /* 40 into 8: FORTIFY / stack canary */
    printf("RESULT probe=oob_write variant=stack outcome=corrupted detail=\"stack buf overflow head=%c; expect trap where hardening on\"\n", buf[0]);
}

int main(int argc, char **argv) {
    const char *v = (argc > 1) ? argv[1] : "intra";
    if (!strcmp(v, "heap")) variant_heap();
    else if (!strcmp(v, "stack")) variant_stack();
    else variant_intra();
    return 0;
}
