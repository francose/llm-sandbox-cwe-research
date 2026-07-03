/*
 * int_overflow_alloc.c -- CWE-190 leading to CWE-131/787.
 *
 * This sits behind a lot of real heap overflows: you size an allocation as
 * malloc(count * size), the multiply overflows size_t, and you get back a tiny buffer
 * that the code then fills as if it were the full size.
 *
 * count comes from argv so it is a real runtime value (an attacker-controlled length
 * is the usual case). I don't write gigabytes to show it -- I just show that
 * malloc(count*size) hands back a small non-NULL buffer while calloc(count,size)
 * returns NULL, because calloc checks the multiply. That difference is the finding:
 * the safe way exists, the malloc(a*b) way skips it.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const size_t size = 24;                       /* per-element size */
    /* default count chosen to overflow size_t*24 on a 64-bit host */
    size_t count = (argc > 1) ? strtoull(argv[1], NULL, 0)
                              : (SIZE_MAX / size) + 2;

    size_t total = count * size;                  /* CWE-190: wraps */
    printf("count=%zu size=%zu  intended=%zu bytes  total(after wrap)=%zu bytes\n",
           count, size, count * size, total);     /* both print the wrapped value */

    char *viamalloc = malloc(total);              /* succeeds: tiny buffer */
    void *viacalloc = calloc(count, size);        /* NULL: overflow detected */

    printf("malloc(count*size) = %p  (%s)\n", (void *)viamalloc,
           viamalloc ? "ALLOCATED tiny buffer" : "null");
    printf("calloc(count,size) = %p  (%s)\n", viacalloc,
           viacalloc ? "allocated" : "REFUSED (overflow checked)");

    int defect = (viamalloc != NULL) && (viacalloc == NULL) && (total < count && count > 1);
    /* total < count when the product wrapped below the operands */

    if (viamalloc) {
        /* one controlled store to show the region is undersized vs intent */
        if (total >= 1) viamalloc[0] = 'A';
        free(viamalloc);
    }
    if (viacalloc) free(viacalloc);

    if (defect)
        printf("RESULT probe=int_overflow_alloc outcome=corrupted detail=\"malloc(count*size) wrapped to undersized buffer; calloc refused\"\n");
    else
        printf("RESULT probe=int_overflow_alloc outcome=clean detail=\"no wrap for this count\"\n");
    return 0;
}
