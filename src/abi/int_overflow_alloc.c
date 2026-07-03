/* int_overflow_alloc.c  --  CWE-190 (integer overflow) -> CWE-131/787 (undersized alloc).
 *
 * The single most common real-world heap-overflow root cause: sizing an
 * allocation with `malloc(count * size)` where the multiply overflows size_t,
 * yielding a tiny buffer that the caller then fills as if it were huge.
 *
 * `count` is taken from argv so the value is genuinely runtime-controlled (an
 * attacker-influenced length is the realistic case). This probe does NOT write
 * gigabytes -- it demonstrates the defect safely:
 *   - malloc(count*size) returns a SMALL non-NULL buffer (the wrap), while
 *   - calloc(count,size) returns NULL because calloc checks the multiply.
 * A single controlled store just past the wrapped size confirms the buffer is
 * smaller than the caller intends. The malloc/calloc split is the finding: the
 * overflow-safe primitive exists, but `malloc(a*b)` -- what agents emit -- skips it.
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
