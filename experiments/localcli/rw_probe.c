// rw_probe.c -- probe READ and WRITE access to each path argument.
// Prints ONLY the allow/deny verdict and errno, never file contents, so it is safe
// to aim at real dotfiles. Built static so execve needs no dynamic loader and no
// library reads -- that keeps the Landlock READ pin (rw_probe cannot read outside the
// project dir) from breaking its own startup.
//   Build: gcc -O2 -static rw_probe.c -o rw_probe
//   Usage: rw_probe <path> [path...]
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *p = argv[i];
        char rbuf[80], wbuf[80];
        int fd = open(p, O_RDONLY);
        if (fd >= 0) { snprintf(rbuf, sizeof rbuf, "ALLOW"); close(fd); }
        else snprintf(rbuf, sizeof rbuf, "DENY(%s)", strerror(errno));
        // O_CREAT but no O_TRUNC: never destroys an existing file's contents.
        fd = open(p, O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) { snprintf(wbuf, sizeof wbuf, "ALLOW"); close(fd); }
        else snprintf(wbuf, sizeof wbuf, "DENY(%s)", strerror(errno));
        printf("path=%-40s read=%-20s write=%s\n", p, rbuf, wbuf);
    }
    return 0;
}
