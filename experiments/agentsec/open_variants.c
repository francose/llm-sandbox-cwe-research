// open_variants.c -- write a path three ways (open / creat / openat) and report which succeeded.
// Shows the seccomp persist gate governs only openat (open + creat slip through, a coverage gap),
// while Landlock governs all three at the same file-open LSM hook.
// Build: gcc -O2 open_variants.c -o open_variants ; Usage: open_variants <path>
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
static const char *r(long fd){ if (fd >= 0){ close((int)fd); return "WROTE"; } return "denied"; }
int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr, "usage: %s <path>\n", argv[0]); return 2; }
    const char *p = argv[1];
    long a = syscall(SYS_open,   p, O_WRONLY | O_CREAT, 0644);
    long b = syscall(SYS_creat,  p, 0644);
    long c = syscall(SYS_openat, AT_FDCWD, p, O_WRONLY | O_CREAT, 0644);
    printf("open=%s creat=%s openat=%s\n", r(a), r(b), r(c));
    return 0;
}
