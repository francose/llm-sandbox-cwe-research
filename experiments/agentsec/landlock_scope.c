// landlock_scope.c -- measures where a Landlock allowlist stops governing.
//
// Part II of the paper benchmarks a Landlock filesystem allowlist against the seccomp
// argument-inspection gate and finds it closes the race, the syscall-alias gap, and the
// substring imprecision. That is a result about the mechanisms it DOES mediate. This probe
// measures the boundary of that set, so the paper states the scope from measurement rather
// than from the documentation.
//
// Each case runs in its own child: landlock_restrict_self() is irreversible per thread.
// The oracle is the kernel's own errno, never a text scan.
//
//   A  execute        -- can Landlock deny execve at all?  (paper claimed it cannot)
//   B  pre-open fd    -- does a descriptor opened BEFORE restrict_self stay writable?
//   C  network scope  -- TCP connect vs UDP sendto vs raw socket under a net ruleset
//
// Build: gcc -O2 landlock_scope.c -o landlock_scope
// Usage: landlock_scope <allowed_dir> <denied_dir> [target_ip]
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif

// The distribution header on this host predates the network ABI, so the ABI>=4 layout is
// declared here. The kernel takes the struct size and accepts a short one for compatibility.
struct ll_ruleset_attr_net { __u64 handled_access_fs; __u64 handled_access_net; };
struct ll_net_port_attr    { __u64 allowed_access;   __u64 port; };
#define LL_RULE_NET_PORT              2
#define LL_ACCESS_NET_BIND_TCP        (1ULL << 0)
#define LL_ACCESS_NET_CONNECT_TCP     (1ULL << 1)

static long ll_create(const void *a, size_t s, uint32_t f){
    return syscall(__NR_landlock_create_ruleset, a, s, f);
}
static long ll_add(int fd, int t, const void *attr, uint32_t f){
    return syscall(__NR_landlock_add_rule, fd, t, attr, f);
}
static long ll_restrict(int fd, uint32_t f){
    return syscall(__NR_landlock_restrict_self, fd, f);
}

static const char *ok_or_errno(int rc){
    static char buf[64];
    if (rc >= 0) return "OK";
    snprintf(buf, sizeof buf, "%s", strerror(errno));
    return buf;
}

// ---------------------------------------------------------------- case A: execute

// handled_access_fs = EXECUTE, with execute granted ONLY beneath <allowed_dir>.
// If Landlock cannot govern execution, /bin/true runs; if it can, execv fails EACCES.
static int case_execute(const char *allowed){
    uint64_t rights = LANDLOCK_ACCESS_FS_EXECUTE;
    struct landlock_ruleset_attr ra = { .handled_access_fs = rights };
    int rs = ll_create(&ra, sizeof ra, 0);
    if (rs < 0){ perror("A create_ruleset"); return 90; }

    int dfd = open(allowed, O_PATH | O_CLOEXEC);
    if (dfd < 0){ perror("A open(allowed)"); return 91; }
    struct landlock_path_beneath_attr pb = { .allowed_access = rights, .parent_fd = dfd };
    if (ll_add(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0){ perror("A add_rule"); return 92; }
    close(dfd);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)){ perror("A no_new_privs"); return 93; }
    if (ll_restrict(rs, 0)){ perror("A restrict_self"); return 94; }
    close(rs);

    char *const av[] = { "/bin/true", NULL };
    execv(av[0], av);
    printf("A  execve(/bin/true) outside allowlist : DENIED (%s)\n", strerror(errno));
    return 0;   // denial is the expected, reportable outcome
}

// ---------------------------------------------------------------- case B: pre-open fd

// Open a file under <denied_dir> for writing, THEN install the write-deny allowlist that
// landlock_gate.c installs, then write through the descriptor that predates the ruleset.
static int case_preopen(const char *allowed, const char *denied){
    char path[4096];
    snprintf(path, sizeof path, "%s/preopen.txt", denied);

    int pre = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pre < 0){ perror("B open(pre)"); return 90; }

    uint64_t write_rights =
        LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_DIR   | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_REMOVE_DIR;

    struct landlock_ruleset_attr ra = { .handled_access_fs = write_rights };
    int rs = ll_create(&ra, sizeof ra, 0);
    if (rs < 0){ perror("B create_ruleset"); return 91; }

    int dfd = open(allowed, O_PATH | O_CLOEXEC);
    if (dfd < 0){ perror("B open(allowed)"); return 92; }
    struct landlock_path_beneath_attr pb = { .allowed_access = write_rights, .parent_fd = dfd };
    if (ll_add(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0){ perror("B add_rule"); return 93; }
    close(dfd);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)){ perror("B no_new_privs"); return 94; }
    if (ll_restrict(rs, 0)){ perror("B restrict_self"); return 95; }
    close(rs);

    // 1: write through the descriptor that predates the ruleset.
    ssize_t w = write(pre, "written through a pre-ruleset descriptor\n", 41);
    printf("B  write() via fd opened BEFORE restrict_self : %s\n",
           w == 41 ? "WROTE" : ok_or_errno(-1));

    // 2: the same path, opened fresh under the ruleset.
    int post = open(path, O_WRONLY | O_APPEND);
    printf("B  open() of the same path AFTER restrict_self: %s\n",
           post >= 0 ? "OPENED" : ok_or_errno(-1));
    if (post >= 0) close(post);
    close(pre);
    return 0;
}

// ---------------------------------------------------------------- case C: network scope

// handled_access_net = CONNECT_TCP with no port granted: every TCP connect must be denied.
// Then ask what the same ruleset does about UDP and about a raw socket.
static const char *net_target = "10.0.0.5";

static int case_network(void){
    struct ll_ruleset_attr_net ra = { .handled_access_fs = 0,
                                      .handled_access_net = LL_ACCESS_NET_CONNECT_TCP };
    int rs = ll_create(&ra, sizeof ra, 0);
    if (rs < 0){
        printf("C  net ruleset unsupported on this kernel (%s)\n", strerror(errno));
        return 0;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)){ perror("C no_new_privs"); return 94; }
    if (ll_restrict(rs, 0)){ perror("C restrict_self"); return 95; }
    close(rs);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(80);
    inet_pton(AF_INET, net_target, &sa.sin_addr);

    int t = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int trc = connect(t, (struct sockaddr *)&sa, sizeof sa);
    // EINPROGRESS means the kernel accepted the call; only EACCES is a Landlock denial.
    printf("C  TCP  connect()  under CONNECT_TCP ruleset : %s\n",
           (trc == 0 || errno == EINPROGRESS) ? "ALLOWED" : ok_or_errno(-1));
    close(t);

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    ssize_t urc = sendto(u, "x", 1, 0, (struct sockaddr *)&sa, sizeof sa);
    printf("C  UDP  sendto()   under CONNECT_TCP ruleset : %s\n",
           urc >= 0 ? "ALLOWED" : ok_or_errno(-1));
    close(u);

    int r = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (r < 0){
        printf("C  RAW  socket()   under CONNECT_TCP ruleset : unavailable (%s)\n", strerror(errno));
    } else {
        ssize_t rrc = sendto(r, "\x45\x00\x00\x14\x00\x00\x00\x00\x40\xff\x00\x00"
                                "\x7f\x00\x00\x01\x7f\x00\x00\x01", 20, 0,
                             (struct sockaddr *)&sa, sizeof sa);
        printf("C  RAW  sendto()   under CONNECT_TCP ruleset : %s\n",
               rrc >= 0 ? "ALLOWED" : ok_or_errno(-1));
        close(r);
    }
    return 0;
}

// ----------------------------------------------------------------

static int run(const char *label, int (*fn)(const char *, const char *),
               const char *a, const char *b){
    pid_t p = fork();
    if (p == 0){ int r = fn(a, b); fflush(NULL); _exit(r); }
    int st = 0;
    waitpid(p, &st, 0);
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    if (rc != 0) fprintf(stderr, "%s: child exited %d\n", label, rc);
    return rc;
}

static int exec_shim(const char *a, const char *b){ (void)b; return case_execute(a); }
static int pre_shim (const char *a, const char *b){ return case_preopen(a, b); }
static int net_shim (const char *a, const char *b){ (void)a; (void)b; return case_network(); }

int main(int argc, char **argv){
    if (argc < 3){ fprintf(stderr, "usage: %s <allowed_dir> <denied_dir> [target_ip]\n", argv[0]); return 2; }
    if (argc > 3) net_target = argv[3];
    setvbuf(stdout, NULL, _IOLBF, 0);   // children _exit(); keep their lines from being lost

    long abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1){ fprintf(stderr, "LANDLOCK_UNAVAILABLE (abi=%ld: %s)\n", abi, strerror(errno)); return 3; }
    printf("landlock ABI = %ld\n", abi);

    int rc = 0;
    rc |= run("A", exec_shim, argv[1], argv[2]);
    rc |= run("B", pre_shim,  argv[1], argv[2]);
    rc |= run("C", net_shim,  argv[1], argv[2]);
    return rc;
}
