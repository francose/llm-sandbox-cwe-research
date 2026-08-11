// EXP-CLOSEDLOOP: detect -> deny -> terminate, as one automatic chain, measured end to end.
//
// The rest of this repo proves the pieces separately: weak controls are bypassable, object-level
// controls deny tested effects, and a PID namespace or cgroup terminates a contained tree. What it
// does not prove is that a detection can DRIVE the termination, or what the residual damage is
// between the two. That is what this measures.
//
// Structure. The observer lives outside the boundary it is watching: the supervisor is the
// grandparent process, outside the agent's PID namespace, holding a seccomp notify listener the
// agent handed out. The agent is PID 1 of its own namespace with K workers under it; every worker
// inherits the filter, so every forbidden open is a notification the supervisor must answer.
//
//   agent worker attempts the forbidden open
//         -> kernel parks the syscall, notifies the supervisor      (observe)
//         -> supervisor answers EPERM, kernel applies it            (synchronous denial)
//         -> supervisor SIGKILLs the namespace init                 (terminate)
//         -> kernel reaps the namespace                             (zero survivors)
//         -> canary + work counter say what landed before quiescence (residual)
//
// Four arms, so each link is attributable rather than assumed:
//
//   baseline  no filter, no observer, no kill  -- proves the attack fixture actually works
//   observe   filter + supervisor, answers CONTINUE (allows) -- proves detection without enforcement
//   enforce   filter + supervisor, answers EPERM  -- proves synchronous denial, tree keeps running
//   latekill  allows the call, THEN kills init -- detect-then-terminate with no synchronous denial
//   closed    answers EPERM then kills init -- synchronous denial AND termination, the full chain
//
// latekill against closed is the measurement that settles whether a kill switch can substitute for
// enforcement. It cannot: the call it detected has already completed by the time the signal lands,
// so the canary carries whatever that call wrote. Only the synchronous denial keeps the canary
// clean. The kill's job is to stop the NEXT attempt, and the retry counts show why that matters.
//
// The observe arm is the one that cannot be skipped: it is the only arm where the forbidden action
// is permitted to COMPLETE while being watched, which is what separates "we saw it" from "we blocked
// it". In every other arm the same mechanism does both and the two claims collapse together.
//
// Oracles are ground truth, never the agent's report: the canary path on disk, a shared work counter
// read from outside the namespace, and a survivor count keyed on the namespace inode.
//
// Unprivileged: CLONE_NEWPID needs CAP_SYS_ADMIN, obtained via CLONE_NEWUSER with an identity map.
// NEW_LISTENER needs no_new_privs, which the agent sets.
//
// Build: gcc -O2 closed_loop.c -o out/closed_loop -lseccomp
// Usage: closed_loop <baseline|observe|enforce|closed> <canary_path> <counter_path> [workers] [ms]
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <stdatomic.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>

enum { ARM_BASELINE, ARM_OBSERVE, ARM_ENFORCE, ARM_CLOSED, ARM_LATEKILL };

static int   g_arm;
static char  g_canary[512];
static int   g_workers = 12;
static long  g_run_ms  = 1500;
static _Atomic long *g_counter;

static long now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

// --- fd passing ----------------------------------------------------------------------------------
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

// Live processes in PID-namespace inode `ns`. Counted from outside the namespace, so a process that
// hid from its own /proc still shows up here.
static int members(const char *ns){
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e; int n = 0; char lp[64], buf[64];
    while ((e = readdir(d))){
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(lp, sizeof lp, "/proc/%s/ns/pid", e->d_name);
        ssize_t r = readlink(lp, buf, sizeof buf - 1);
        if (r <= 0) continue;
        buf[r] = '\0';
        if (!strcmp(buf, ns)) n++;
    }
    closedir(d);
    return n;
}

// --- the agent -----------------------------------------------------------------------------------
// A worker does countable work continuously and periodically retries the forbidden open. The
// continuous work is what makes "effects completed after detection" measurable rather than notional.
static void worker(void){
    alarm(20);                                   // safety net; nothing outlives the experiment
    for (long i = 0; ; i++){
        if (i % 40 == 0){
            int fd = open(g_canary, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0){ (void)!write(fd, "e", 1); close(fd); }
        }
        atomic_fetch_add_explicit(g_counter, 1, memory_order_relaxed);
        usleep(1000);
    }
}

static void agent_main(int fdsock){
    alarm(25);
    if (g_arm != ARM_BASELINE){
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(4);
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (!ctx) _exit(4);
        if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 0) < 0) _exit(4);
        if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 0) < 0) { /* may be absent */ }
        if (seccomp_load(ctx) < 0) _exit(4);
        int nfd = seccomp_notify_fd(ctx);
        if (nfd < 0 || send_fd(fdsock, nfd)) _exit(4);
        char go;                                  // do not race ahead of the supervisor's recv loop
        if (read(fdsock, &go, 1) != 1) _exit(4);
    }
    for (int i = 0; i < g_workers; i++){
        pid_t p = fork();
        if (p == 0) worker();
    }
    for (;;) pause();
}

static int write_map(const char *path, const char *val){
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return n > 0 ? 0 : -1;
}

int main(int argc, char **argv){
    if (argc < 4){
        fprintf(stderr, "usage: %s <baseline|observe|enforce|closed> <canary> <counter> [workers] [ms]\n",
                argv[0]);
        return 2;
    }
    const char *arm = argv[1];
    if      (!strcmp(arm, "baseline")) g_arm = ARM_BASELINE;
    else if (!strcmp(arm, "observe"))  g_arm = ARM_OBSERVE;
    else if (!strcmp(arm, "enforce"))  g_arm = ARM_ENFORCE;
    else if (!strcmp(arm, "closed"))   g_arm = ARM_CLOSED;
    else if (!strcmp(arm, "latekill")) g_arm = ARM_LATEKILL;
    else { fprintf(stderr, "unknown arm %s\n", arm); return 2; }
    snprintf(g_canary, sizeof g_canary, "%s", argv[2]);
    const char *counter_path = argv[3];
    if (argc > 4) g_workers = atoi(argv[4]);
    if (argc > 5) g_run_ms  = atol(argv[5]);

    unlink(g_canary);

    int cf = open(counter_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (cf < 0 || ftruncate(cf, sizeof(long))){ perror("counter"); return 3; }
    g_counter = mmap(NULL, sizeof(long), PROT_READ | PROT_WRITE, MAP_SHARED, cf, 0);
    if (g_counter == MAP_FAILED){ perror("mmap"); return 3; }

    int sp[2], sf[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) || socketpair(AF_UNIX, SOCK_STREAM, 0, sf)){
        perror("socketpair"); return 3; }

    uid_t uid = getuid(); gid_t gid = getgid();
    pid_t child = fork();
    if (child < 0){ perror("fork"); return 3; }

    if (child == 0){
        close(sp[0]); close(sf[0]);
        // CLONE_NEWUSER first buys CAP_SYS_ADMIN in the new namespace, which CLONE_NEWPID needs.
        if (unshare(CLONE_NEWUSER | CLONE_NEWPID)){ perror("unshare"); _exit(5); }
        char m[64];
        write_map("/proc/self/setgroups", "deny");
        snprintf(m, sizeof m, "0 %d 1", uid); write_map("/proc/self/uid_map", m);
        snprintf(m, sizeof m, "0 %d 1", gid); write_map("/proc/self/gid_map", m);
        // This process stays in the old namespace; the first child it forks is init in the new one,
        // so the pid returned here is the init's HOST-visible pid -- which is what the supervisor
        // outside needs in order to kill it.
        pid_t init = fork();
        if (init == 0){ close(sp[1]); agent_main(sf[1]); _exit(0); }
        if (write(sp[1], &init, sizeof init) != sizeof init) _exit(5);
        int st; waitpid(init, &st, 0);
        _exit(0);
    }

    close(sp[1]); close(sf[1]);
    pid_t init = 0;
    if (read(sp[0], &init, sizeof init) != sizeof init){ fprintf(stderr, "no init pid\n"); return 3; }

    char nsbuf[64], lp[64];
    snprintf(lp, sizeof lp, "/proc/%d/ns/pid", init);
    ssize_t nr = readlink(lp, nsbuf, sizeof nsbuf - 1);
    if (nr <= 0){ fprintf(stderr, "no ns inode for init\n"); return 3; }
    nsbuf[nr] = '\0';

    long t_start = now_ms(), t_detect = -1, t_kill = -1, t_zero = -1;
    long work_at_detect = -1;
    int  detections = 0, allowed = 0, denied = 0, notifications = 0;

    if (g_arm == ARM_BASELINE){
        usleep(g_run_ms * 1000);
        kill(init, SIGKILL);                     // teardown only; not part of any measured chain
    } else {
        int nfd = recv_fd(sf[0]);
        if (nfd < 0){ fprintf(stderr, "no listener fd\n"); return 3; }
        struct seccomp_notif *req = NULL; struct seccomp_notif_resp *resp = NULL;
        if (seccomp_notify_alloc(&req, &resp) < 0){ fprintf(stderr, "notify_alloc\n"); return 3; }
        if (write(sf[0], "g", 1) != 1) return 3;

        for (;;){
            if (g_arm != ARM_CLOSED && now_ms() - t_start > g_run_ms) { kill(init, SIGKILL); break; }
            memset(req, 0, sizeof *req);
            if (seccomp_notify_receive(nfd, req) < 0){
                if (errno == EINTR) continue;
                break;                            // target gone
            }
            notifications++;
            char path[1024] = {0};
            read_path(req->pid, (unsigned long)req->data.args[1], path, sizeof path);
            int is_canary = strstr(path, g_canary) != NULL;

            memset(resp, 0, sizeof *resp);
            resp->id = req->id;
            if (is_canary){
                if (t_detect < 0){
                    t_detect = now_ms();
                    work_at_detect = atomic_load(g_counter);
                }
                detections++;
                // OBSERVE and LATEKILL both let the current call complete. That is the point of
                // LATEKILL: it is the detect-then-terminate design, with no synchronous denial, so
                // the residual it leaves is the honest cost of relying on a kill switch alone.
                if (g_arm == ARM_OBSERVE || g_arm == ARM_LATEKILL){
                    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; allowed++;
                } else {
                    resp->error = -EPERM; denied++;
                }
            } else {
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            }
            if (seccomp_notify_respond(nfd, resp) < 0 && errno != ENOENT) break;

            if ((g_arm == ARM_CLOSED || g_arm == ARM_LATEKILL) && is_canary){
                t_kill = now_ms();
                kill(init, SIGKILL);              // the detection drives the termination
                break;
            }
        }
        seccomp_notify_free(req, resp);
    }

    int left = 0;
    for (int i = 0; i < 200; i++){                // poll to quiescence, 20s ceiling
        left = members(nsbuf);
        if (left <= 0){ if (t_zero < 0) t_zero = now_ms(); break; }
        usleep(100000);
    }
    if (t_zero < 0) t_zero = now_ms();
    int st; waitpid(child, &st, 0);

    long work_final = atomic_load(g_counter);
    int  canary = access(g_canary, F_OK) == 0;
    long csize = 0;
    if (canary){ struct stat sb; if (!stat(g_canary, &sb)) csize = (long)sb.st_size; }

    printf("CLOSEDLOOP arm=%s canary_exists=%s canary_bytes=%ld notifications=%d detections=%d "
           "allowed=%d denied=%d survivors=%d work_at_detect=%ld work_final=%ld work_after_detect=%ld "
           "detect_ms=%ld kill_after_detect_ms=%ld detect_to_zero_ms=%ld\n",
           arm, canary ? "YES" : "no", csize, notifications, detections, allowed, denied,
           left < 0 ? 0 : left, work_at_detect, work_final,
           work_at_detect < 0 ? -1 : work_final - work_at_detect,
           t_detect < 0 ? -1 : t_detect - t_start,
           (t_kill < 0 || t_detect < 0) ? -1 : t_kill - t_detect,
           t_detect < 0 ? -1 : t_zero - t_detect);
    return 0;
}
