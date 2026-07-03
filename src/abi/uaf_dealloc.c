/* uaf_dealloc.c  --  CWE-416 (use-after-free) and freed-memory residency.
 *
 * Answers two runtime-memory questions the study kept raising:
 *   (a) When an agent frees a buffer that held a secret, does the data leave
 *       memory, or stay resident and readable through the dangling pointer?
 *   (b) Does the default allocator catch the use-after-free?
 *
 * Verified behaviour (glibc, this host):
 *   - free() does NOT scrub. The chunk goes to tcache; glibc writes ~16 bytes of
 *     metadata (next pointer + safe-linking key) over the HEAD of the freed
 *     chunk, but everything past that stays byte-for-byte resident. A secret
 *     longer than the metadata therefore survives "deallocation".
 *   - The default allocator does NOT detect the dangling read. Under ASan the
 *     same read TRAPS (heap-use-after-free) -- the runtime-layer defense, off in
 *     a normal build.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char secret[96];
    memset(secret, 0, sizeof secret);
    strcpy(secret,
           "HEAD____________TAIL_SECRET_TOKEN_survives_past_tcache_metadata_0xC0FFEE_leak");
    size_t n = sizeof secret;

    char *p = malloc(n);
    if (!p) return 2;
    memcpy(p, secret, n);
    printf("before free: \"%s\"\n", p);

    free(p);   /* dealloc */

    /* Dangling read (UAF). Traps under ASan; silent otherwise. */
    volatile char *d = (volatile char *)p;
    int head_intact  = memcmp((void *)d, secret, 16) == 0;          /* clobbered by tcache */
    int tail_bytes   = 0;
    for (size_t i = 32; i < n; i++)
        if (d[i] == secret[i]) tail_bytes++;
    int tail_resident = tail_bytes == (int)(n - 32);

    printf("after free : head_intact=%d  tail_resident=%d (%d/%zu bytes)  head16=",
           head_intact, tail_resident, tail_bytes, n - 32);
    for (int i = 0; i < 16; i++) printf("%02x", (unsigned char)d[i]);
    printf("\n");
    if (tail_resident)
        printf("after free : recovered tail -> \"%s\"\n", (const char *)d + 32);

    if (tail_resident)
        printf("RESULT probe=uaf_dealloc outcome=corrupted detail=\"free() does not scrub: %d tail bytes of secret readable after free; UAF undetected\"\n", tail_bytes);
    else
        printf("RESULT probe=uaf_dealloc outcome=clean detail=\"freed memory not readable\"\n");
    return 0;
}
