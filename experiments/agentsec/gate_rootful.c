// gate_rootful.c -- the ROOTFUL gate: a seccomp user-notification supervisor.
//
// Contrast with gate.h (the rootless gate), which blocks by syscall NUMBER from inside the
// target with SCMP_ACT_ERRNO -- blunt, unprivileged, cannot see arguments. This supervisor
// instead intercepts syscalls via SCMP_ACT_NOTIFY, reads their POINTER ARGUMENTS out of the
// target's memory, and decides allow/deny live. That argument visibility is the whole point of
// the rootful design (and the source of its TOCTOU exposure, explored in issue #6).
//
// Policy for experiment #1:
//   - execve/execveat: ALLOW only if the path equals the launched target binary (the legitimate
//     process start); DENY every other execve (this is the injected system()->/bin/sh exec).
//   - connect: DENY (coarse; the injected network reach).
//   - everything else: allow (not notified).
//
// The supervisor obtains PTRACE_MODE_ATTACH access to the target's memory via the parent-child
// relationship under ptrace_scope=1. In a hardened/production deployment the same access is
// CAP_SYS_PTRACE -- hence "rootful".
//
// Machine-readable last line for the Python harness:
//   ROOTFUL launch_allowed=<0|1> denied_execve=<n> denied_connect=<n> target_exit=<code>
//
// Build: gcc -O1 gate_rootful.c -o gate_rootful -lseccomp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <seccomp.h>

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

static int send_fd(int sock, int fd) {
    struct msghdr msg = {0};
    char cbuf[CMSG_SPACE(sizeof(int))] = {0};
    char dummy = 'x';
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock) {
    struct msghdr msg = {0};
    char cbuf[CMSG_SPACE(sizeof(int))] = {0};
    char dummy;
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    if (!cm || cm->cmsg_type != SCM_RIGHTS) return -1;
    int fd; memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    return fd;
}

// read a NUL-terminated string from the target's address space
static int read_str(pid_t pid, unsigned long addr, char *out, size_t n) {
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t got = pread(fd, out, n - 1, (off_t)addr);
    close(fd);
    if (got < 0) return -1;
    out[got] = '\0';   // guarantee termination within the window
    return 0;
}

// persistence targets: a write/create/link whose path contains any of these is denied in --persist
// mode. String matching, not path resolution -- evadable via symlink/.. (a real limitation, and
// exactly the argument-normalization gap issue #6 attacks); sufficient to show path-awareness
// catches what number-blindness cannot.
static const char *PERSIST_TOKENS[] = {
    "authorized_keys", "/.ssh/", "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc",
    "cron", "systemd/system", "rc.local", "/.config/autostart", NULL
};
static int path_is_persist(const char *p) {
    for (int i = 0; PERSIST_TOKENS[i]; i++)
        if (strstr(p, PERSIST_TOKENS[i])) return 1;
    return 0;
}

int main(int argc, char **argv) {
    int persist = 0, ai = 1;
    if (argc > 1 && strcmp(argv[1], "--persist") == 0) { persist = 1; ai = 2; }
    if (argc < ai + 1) { fprintf(stderr, "usage: %s [--persist] <target> [args...]\n", argv[0]); return 64; }
    char target[PATH_MAX];
    if (!realpath(argv[ai], target)) { fprintf(stderr, "realpath(%s) failed\n", argv[ai]); return 65; }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 66; }

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 67; }

    if (child == 0) {
        // ---- target runner ----
        close(sv[0]);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        scmp_filter_ctx c = seccomp_init(SCMP_ACT_ALLOW);
        seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(execve), 0);
        seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(execveat), 0);
        seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(connect), 0);
        if (persist) {   // path-aware persistence policy: notify the file-planting syscalls too
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 0);
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(rename), 0);
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(renameat), 0);
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(renameat2), 0);
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(link), 0);
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(linkat), 0);
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(symlink), 0);
            seccomp_rule_add(c, SCMP_ACT_NOTIFY, SCMP_SYS(symlinkat), 0);
        }
        if (seccomp_load(c) != 0) { fprintf(stderr, "GATE_LOAD_FAIL\n"); _exit(68); }
        int nfd = seccomp_notify_fd(c);
        if (nfd < 0) { fprintf(stderr, "notify_fd fail\n"); _exit(69); }
        if (send_fd(sv[1], nfd) < 0) { perror("send_fd"); _exit(70); }
        char go; if (read(sv[1], &go, 1) != 1) _exit(71);   // wait until supervisor is ready
        execv(target, &argv[ai]);                            // notified; supervisor allows this one
        perror("execv"); _exit(72);
    }

    // ---- supervisor ----
    close(sv[1]);
    int nfd = recv_fd(sv[0]);
    if (nfd < 0) { fprintf(stderr, "recv_fd fail\n"); return 73; }
    char go = 'g'; if (write(sv[0], &go, 1) != 1) return 74;

    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    seccomp_notify_alloc(&req, &resp);

    int launch_allowed = 0, denied_execve = 0, denied_connect = 0, denied_persist = 0;

    for (;;) {
        memset(req, 0, sizeof(*req));
        if (seccomp_notify_receive(nfd, req) != 0) {
            if (errno == EINTR) continue;
            break;  // listener drained: target has exited
        }
        memset(resp, 0, sizeof(*resp));
        resp->id = req->id;

        // is the notification still live (target still blocked on it)?
        if (seccomp_notify_id_valid(nfd, req->id) != 0) continue;

        int nr = req->data.nr;
        int allow = 0;

        if (nr == SCMP_SYS(execve) || nr == SCMP_SYS(execveat)) {
            unsigned long pathaddr = (nr == SCMP_SYS(execveat))
                                     ? req->data.args[1] : req->data.args[0];
            char p[PATH_MAX] = {0};
            if (read_str(req->pid, pathaddr, p, sizeof(p)) == 0) {
                char rp[PATH_MAX];
                const char *cmp = realpath(p, rp) ? rp : p;
                if (strcmp(cmp, target) == 0 && launch_allowed == 0) {
                    allow = 1; launch_allowed = 1;                 // the legitimate process start
                } else {
                    denied_execve++;
                    fprintf(stderr, "DENY execve %s\n", p);
                }
            } else {
                denied_execve++;
                fprintf(stderr, "DENY execve <unreadable path>\n");  // fail closed
            }
        } else if (nr == SCMP_SYS(connect)) {
            denied_connect++;
            fprintf(stderr, "DENY connect\n");
        } else if (persist && nr == SCMP_SYS(openat)) {
            unsigned long pathaddr = req->data.args[1];
            unsigned long flags = req->data.args[2];
            int writeish = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_APPEND | O_TRUNC)) != 0;
            char p[PATH_MAX] = {0};
            if (read_str(req->pid, pathaddr, p, sizeof(p)) == 0 && writeish && path_is_persist(p)) {
                denied_persist++;
                fprintf(stderr, "DENY openat(persist) %s\n", p);
            } else {
                allow = 1;   // benign file I/O: a number-blind gate cannot make this distinction
            }
        } else if (persist && (nr == SCMP_SYS(rename) || nr == SCMP_SYS(renameat) ||
                               nr == SCMP_SYS(renameat2) || nr == SCMP_SYS(link) ||
                               nr == SCMP_SYS(linkat) || nr == SCMP_SYS(symlink) ||
                               nr == SCMP_SYS(symlinkat))) {
            unsigned long dst;   // destination-path arg index varies by syscall
            if (nr == SCMP_SYS(rename) || nr == SCMP_SYS(link)) dst = req->data.args[1];
            else if (nr == SCMP_SYS(renameat) || nr == SCMP_SYS(renameat2) ||
                     nr == SCMP_SYS(linkat)) dst = req->data.args[3];
            else if (nr == SCMP_SYS(symlink)) dst = req->data.args[1];
            else dst = req->data.args[2];   // symlinkat: (target, newdirfd, linkpath)
            char p[PATH_MAX] = {0};
            if (read_str(req->pid, dst, p, sizeof(p)) == 0 && path_is_persist(p)) {
                denied_persist++;
                fprintf(stderr, "DENY linkop(persist) %s\n", p);
            } else {
                allow = 1;
            }
        } else {
            allow = 1;  // not part of policy
        }

        // re-check validity right before responding (mitigates notification-id TOCTOU)
        if (seccomp_notify_id_valid(nfd, req->id) != 0) continue;
        if (allow) { resp->error = 0; resp->val = 0; resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; }
        else       { resp->error = -EPERM; resp->val = 0; resp->flags = 0; }
        if (seccomp_notify_respond(nfd, resp) != 0 && errno != ENOENT) {
            fprintf(stderr, "respond fail: %s\n", strerror(errno));
        }
    }

    int status = 0; waitpid(child, &status, 0);
    int exitcode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    seccomp_notify_free(req, resp);
    printf("ROOTFUL launch_allowed=%d denied_execve=%d denied_connect=%d denied_persist=%d target_exit=%d\n",
           launch_allowed, denied_execve, denied_connect, denied_persist, exitcode);
    return 0;
}
