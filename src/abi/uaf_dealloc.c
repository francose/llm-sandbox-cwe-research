/*
 * uaf_dealloc.c -- CWE-416 (use-after-free) and what stays in freed memory.
 *
 * Two questions I kept coming back to:
 *   - When we free a buffer that held a secret, does the secret actually leave memory,
 *     or can we still read it through the old pointer?
 *   - Does the normal allocator notice the use-after-free?
 *
 * What I saw with glibc on this machine: free() doesn't wipe anything. The chunk goes
 * on tcache and glibc writes about 16 bytes of its own bookkeeping over the start of
 * it, but everything after that is still there byte for byte, so a secret longer than
 * 16 bytes survives the free. The normal allocator doesn't catch the stale read
 * either; only AddressSanitizer does, and we don't ship that.
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
