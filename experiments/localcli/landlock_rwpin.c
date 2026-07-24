// landlock_rwpin.c -- a true READ+WRITE hard-pin, extended from experiments/agentsec/landlock_gate.c.
//
// The original landlock_gate.c handles only WRITE/CREATE/REMOVE rights and leaves reads ungoverned
// (so a dynamically-linked target can still load its libraries). That is the wrong posture for a
// LOCAL CLI agent whose primary risk is READING the developer's secrets (~/.ssh, dotfiles, env-backed
// token files). This copy additionally handles READ_FILE and READ_DIR, granting read+write ONLY
// beneath <allowed_dir>. Everything else -- the home directory, ~/.ssh, dotfiles -- becomes deny-by-
// default for both read and write. execve is deliberately left ungoverned, so a *static* target execs
// normally without needing a read grant on /lib, /usr, or /etc.
//
// Policy: default-deny filesystem READ and WRITE; grant read+write only beneath <allowed_dir>.
// Build: gcc -O2 landlock_rwpin.c -o landlock_rwpin
// Usage: landlock_rwpin <allowed_dir> <target> [args...]
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

    // READ + WRITE/CREATE/REMOVE rights (all present since ABI v1). EXECUTE is deliberately NOT
    // handled, so exec stays allowed and a static target runs. Reads are now governed, which is the
    // whole point: outside the pin, opening a file for read is denied.
    uint64_t rw_rights =
        LANDLOCK_ACCESS_FS_READ_FILE  |
        LANDLOCK_ACCESS_FS_READ_DIR   |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_REG   |
        LANDLOCK_ACCESS_FS_MAKE_DIR   |
        LANDLOCK_ACCESS_FS_REMOVE_FILE|
        LANDLOCK_ACCESS_FS_REMOVE_DIR;

    struct landlock_ruleset_attr ra = { .handled_access_fs = rw_rights };
    int rs = ll_create(&ra, sizeof(ra), 0);
    if (rs < 0){ perror("create_ruleset"); return 4; }

    int dfd = open(allowed, O_PATH | O_CLOEXEC);
    if (dfd < 0){ perror("open(allowed_dir)"); return 5; }
    struct landlock_path_beneath_attr pb = { .allowed_access = rw_rights, .parent_fd = dfd };
    if (ll_add(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0){ perror("add_rule"); return 6; }
    close(dfd);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)){ perror("no_new_privs"); return 7; }
    if (ll_restrict(rs, 0)){ perror("restrict_self"); return 8; }
    close(rs);

    execv(argv[2], &argv[2]);   // enforced from here on
    perror("execv"); return 9;
}
