// pre-flight: does a seccomp-BPF self-filter deterministically block a syscall on this WSL2 kernel?
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <seccomp.h>

int main(int argc, char** argv) {
    int enforce = (argc > 1 && strcmp(argv[1], "enforce") == 0);
    if (enforce) {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);   // default allow
        // block connect() with EPERM (deterministic, by syscall number, no arg deref)
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0);
        if (seccomp_load(ctx) != 0) { fprintf(stderr, "SECCOMP_LOAD_FAILED\n"); return 3; }
        seccomp_release(ctx);
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(9); a.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1:9
    int r = connect(s, (struct sockaddr*)&a, sizeof(a));
    if (r == 0)            { printf("CONNECT_OK\n");                return 0; }
    if (errno == EPERM)    { printf("BLOCKED_EPERM\n");            return 1; }
    printf("CONNECT_FAIL errno=%d(%s)\n", errno, strerror(errno));  return 2;
}
