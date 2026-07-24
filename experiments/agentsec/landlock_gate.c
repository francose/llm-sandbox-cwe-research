// landlock_gate.c -- the race-free successor to the seccomp argument-inspection gate.
//
// The seccomp user-notification gate (gate_rootful.c) validates a pathname it reads from the
// target's memory, then lets the kernel RE-READ that pointer (SECCOMP_USER_NOTIF_FLAG_CONTINUE) --
// the TOCTOU window EXP-11 exploits. Landlock has no such window: the policy is a default-deny
// allowlist evaluated in-kernel against the RESOLVED path, once, at the LSM hook. There is no
// user-space "check" for a second thread to invalidate, and the rule set covers every path that
// reaches the file-open / remove / rename hooks -- so open/openat/openat2/creat are all governed
// uniformly (closing the syscall-alias gap of Section on coverage), and paths are resolved, not
// substring-matched (closing the strstr false-positive/evasion trade-off).
//
// Policy: default-deny all filesystem WRITE/CREATE/REMOVE; grant them only beneath <allowed_dir>.
// Reads and execution are left ungoverned so the target and its libraries load normally.
//
// Build: gcc -O2 landlock_gate.c -o landlock_gate
// Usage: landlock_gate <allowed_dir> <target> [args...]
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
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

static long ll_create(const struct landlock_ruleset_attr *a, size_t s, uint32_t f){
    return syscall(__NR_landlock_create_ruleset, a, s, f);
}
static long ll_add(int fd, enum landlock_rule_type t, const void *attr, uint32_t f){
    return syscall(__NR_landlock_add_rule, fd, t, attr, f);
}
static long ll_restrict(int fd, uint32_t f){
    return syscall(__NR_landlock_restrict_self, fd, f);
}

int main(int argc, char **argv){
    if (argc < 3){ fprintf(stderr, "usage: %s <allowed_dir> <target> [args...]\n", argv[0]); return 2; }
    const char *allowed = argv[1];

    long abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1){ fprintf(stderr, "LANDLOCK_UNAVAILABLE (abi=%ld: %s)\n", abi, strerror(errno)); return 3; }

    // WRITE/CREATE/REMOVE rights, all present since ABI v1. Reads/exec deliberately NOT handled,
    // so they stay allowed and the loader works.
    uint64_t write_rights =
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_REG   |
        LANDLOCK_ACCESS_FS_MAKE_DIR   |
        LANDLOCK_ACCESS_FS_REMOVE_FILE|
        LANDLOCK_ACCESS_FS_REMOVE_DIR;

    struct landlock_ruleset_attr ra = { .handled_access_fs = write_rights };
    int rs = ll_create(&ra, sizeof(ra), 0);
    if (rs < 0){ perror("create_ruleset"); return 4; }

    int dfd = open(allowed, O_PATH | O_CLOEXEC);
    if (dfd < 0){ perror("open(allowed_dir)"); return 5; }
    struct landlock_path_beneath_attr pb = { .allowed_access = write_rights, .parent_fd = dfd };
    if (ll_add(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0){ perror("add_rule"); return 6; }
    close(dfd);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)){ perror("no_new_privs"); return 7; }
    if (ll_restrict(rs, 0)){ perror("restrict_self"); return 8; }
    close(rs);

    execv(argv[2], &argv[2]);   // enforced from here on
    perror("execv"); return 9;
}
