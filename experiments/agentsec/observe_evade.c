// EXP-OBSERVE: which observation channel can the observed process detect, and therefore evade?
//
// "The agent's behaviour is observable" is only worth something if the agent cannot tell it is being
// observed. This probe separates two channels that both claim to give a syscall-level view:
//
//   ptrace/strace  -- an attachment the target can read off its own /proc/self/status TracerPid
//   seccomp notify -- a filter the target installed on itself; there is no tracer, and the kernel
//                     parks the syscall until a supervisor holding the listener fd answers
//
// The target here is deliberately evasive in the way real malware is: it checks TracerPid and does the
// benign thing when it believes it is being watched. Run it three ways and compare what each observer
// concluded against what actually happened on disk.
//
//   bare    : no observer.                 Expect TracerPid=0 -> writes the evil path.
//   strace  : run `bare` under strace -f.  Expect TracerPid!=0 -> writes the benign path, and the
//             trace faithfully records a clean run, because observing changed the behaviour.
//   notify  : supervisor + seccomp notify. Expect TracerPid=0 (nothing to detect) -> the target tries
//             the evil path, and the supervisor both sees it and denies it.
//
// Ground truth is the filesystem, never the target's own report: after each arm, does the evil path
// exist? The deny path answers SCMP_ACT_NOTIFY with an errno, which the kernel applies itself; the
// CONTINUE flag is used only to let benign calls through, and is not on the deny path (Part I of the
// paper is precisely about why a CONTINUE allow-path decision is raceable).
//
// Unprivileged: NEW_LISTENER needs either CAP_SYS_ADMIN or no_new_privs, and we set no_new_privs.
//
// Build: gcc -O2 observe_evade.c -o observe_evade -lseccomp
// Usage: observe_evade <bare|notify> <benign_path> <evil_path>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

static char g_benign[512], g_evil[512];

// TracerPid is nonzero exactly when something is ptrace-attached. This is the whole evasion: one
// line, no privilege, and it is how the target decides which of two behaviours to show.
static int tracer_pid(void){
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256]; int t = 0;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "TracerPid:", 10)) { t = atoi(line + 10); break; }
    fclose(f);
    return t;
}

// The agent. Benign when watched, hostile when it believes it is not.
static void behave(void){
    int t = tracer_pid();
    const char *target = (t != 0) ? g_benign : g_evil;
    int fd = open(target, O_WRONLY | O_CREAT, 0644);
    int e = errno;
    if (fd >= 0){ (void)!write(fd, "x", 1); close(fd); }
    printf("AGENT tracer_pid=%d chose=%s open=%s\n",
           t, (t != 0) ? "benign" : "evil", fd >= 0 ? "ok" : strerror(e));
    fflush(stdout);
}

// --- fd passing over a socketpair ----------------------------------------------------------------
static int send_fd(int sock, int fd){
    char b = 'F';
    struct iovec io = { .iov_base = &b, .iov_len = 1 };
    char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof cbuf);
    struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(sock, &m, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock){
    char b;
    struct iovec io = { .iov_base = &b, .iov_len = 1 };
    char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof cbuf);
    struct msghdr m = { .msg_iov = &io, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    if (recvmsg(sock, &m, 0) <= 0) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd; memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

// Read the pathname argument out of the notified process. The supervisor never trusts a copy the
// target handed it; it reads the target's memory at the pointer the kernel reported.
static int read_path(pid_t pid, unsigned long addr, char *out, size_t n){
    char p[64]; snprintf(p, sizeof p, "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = pread(fd, out, n - 1, (off_t)addr);
    close(fd);
    if (r <= 0) return -1;
    out[r] = '\0';
    return 0;
}

int main(int argc, char **argv){
    if (argc < 4){ fprintf(stderr, "usage: %s <bare|notify> <benign> <evil>\n", argv[0]); return 2; }
    snprintf(g_benign, sizeof g_benign, "%s", argv[2]);
    snprintf(g_evil,   sizeof g_evil,   "%s", argv[3]);

    if (!strcmp(argv[1], "bare")){ behave(); return 0; }
    if (strcmp(argv[1], "notify")){ fprintf(stderr, "unknown mode %s\n", argv[1]); return 2; }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); return 3; }

    pid_t pid = fork();
    if (pid < 0){ perror("fork"); return 3; }

    if (pid == 0){                                   // ---- the agent, under its own notify filter
        close(sv[0]);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)){ perror("nnp"); _exit(4); }
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (!ctx){ fprintf(stderr, "seccomp_init failed\n"); _exit(4); }
        if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 0) < 0){
            fprintf(stderr, "rule_add failed\n"); _exit(4); }
        if (seccomp_load(ctx) < 0){ fprintf(stderr, "seccomp_load failed\n"); _exit(4); }
        int nfd = seccomp_notify_fd(ctx);
        if (nfd < 0 || send_fd(sv[1], nfd)){ fprintf(stderr, "listener handoff failed\n"); _exit(4); }
        char go;                                     // wait until the supervisor is in its recv loop,
        if (read(sv[1], &go, 1) != 1) _exit(4);      // else the first openat parks with no one home
        behave();
        _exit(0);
    }

    // ---- the supervisor
    close(sv[1]);
    int nfd = recv_fd(sv[0]);
    if (nfd < 0){ fprintf(stderr, "no listener fd\n"); return 3; }

    struct seccomp_notif *req = NULL; struct seccomp_notif_resp *resp = NULL;
    if (seccomp_notify_alloc(&req, &resp) < 0){ fprintf(stderr, "notify_alloc failed\n"); return 3; }
    if (write(sv[0], "g", 1) != 1) return 3;

    int seen_evil = 0, denied = 0, seen_total = 0;
    for (;;){
        memset(req, 0, sizeof *req);
        if (seccomp_notify_receive(nfd, req) < 0){
            if (errno == EINTR) continue;
            break;                                    // ENOENT/EBADF once the target is gone
        }
        char path[1024] = {0};
        read_path(req->pid, (unsigned long)req->data.args[1], path, sizeof path);
        seen_total++;
        memset(resp, 0, sizeof *resp);
        resp->id = req->id;
        if (strstr(path, g_evil)){
            seen_evil++; denied++;
            resp->error = -EPERM; resp->val = 0; resp->flags = 0;      // kernel applies the errno
            printf("SUPERVISOR saw openat(\"%s\") -> DENY EPERM\n", path);
            fflush(stdout);
        } else {
            resp->error = 0; resp->val = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;            // benign: let it run
        }
        if (seccomp_notify_respond(nfd, resp) < 0 && errno != ENOENT) break;
    }

    int st = 0; waitpid(pid, &st, 0);
    printf("SUPERVISOR_RESULT notifications=%d evil_seen=%d denied=%d\n", seen_total, seen_evil, denied);
    seccomp_notify_free(req, resp);
    return 0;
}
