// composed_probe.c -- the composed sandbox of Part IV, attacked end-to-end.
//
// Part I measured a single control failing. Part IV assembles the SOUND successors into one
// sandbox and attacks it against explicitly-stated invariants, binding each invariant to the layer
// that actually enforces it (not to "whatever held"):
//
//   I1 filesystem : Landlock default-deny WRITE/CREATE/REMOVE allowlist beneath <scratch>
//   I2 execution  : seccomp SCMP_ACT_ERRNO deny of execve/execveat (deterministic, no CONTINUE)
//   I3 network    : empty network namespace (no route) -- enforced by the caller's `unshare -rn`
//   I4 proc-tree  : cgroup.kill  -- PRIVILEGED, measured separately in killswitch.sh
//   I5 resources  : cgroup {pids,memory}.max -- PRIVILEGED, measured separately
//
// This binary applies I1+I2 to itself, relies on the caller for I3's namespace, then runs each
// attack in its own fork() child (all three layers are inherited across fork) and reads the
// oracle from the kernel: the errno the call returns AND the ground truth (does the evil path
// exist / did the packet leave). No text scanning. I4/I5 are out of scope here by construction --
// they need a writable cgroup, which this host does not delegate to an unprivileged user.
//
// These are hand-written probes. A probe mutates memory or submits a ring op; it is not "the agent."
//
// Build: gcc -O2 composed_probe.c -o composed_probe
// Usage: unshare -rn composed_probe <scratch_dir> <evil_path_outside_scratch>
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/io_uring.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

static long ll_create(const struct landlock_ruleset_attr *a, size_t s, uint32_t f){
    return syscall(__NR_landlock_create_ruleset, a, s, f);
}
static long ll_add(int fd, enum landlock_rule_type t, const void *attr, uint32_t f){
    return syscall(__NR_landlock_add_rule, fd, t, attr, f);
}
static long ll_restrict(int fd, uint32_t f){ return syscall(__NR_landlock_restrict_self, fd, f); }

// ---- I2: seccomp filter, deny execve/execveat with EPERM, allow everything else -------------
// Arch-guarded so an unexpected ABI kills rather than silently allows (the Part I x32 lesson).
static int install_exec_deny(void){
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_THREAD),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        // x32 syscalls carry bit 30; treat them as denied rather than aliasing x86_64 numbers.
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 0x40000000, 4, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execve,   3, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execveat, 2, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),   // (unreached filler for jt math clarity)
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog = { .len = sizeof(f)/sizeof(f[0]), .filter = f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

// ---- I1: Landlock default-deny write allowlist beneath scratch ------------------------------
static int install_landlock(const char *scratch){
    long abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return -1;
    uint64_t w = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
                 LANDLOCK_ACCESS_FS_MAKE_DIR   | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                 LANDLOCK_ACCESS_FS_REMOVE_DIR;
    struct landlock_ruleset_attr ra = { .handled_access_fs = w };
    int rs = ll_create(&ra, sizeof(ra), 0);
    if (rs < 0) return -2;
    int dfd = open(scratch, O_PATH | O_CLOEXEC);
    if (dfd < 0) return -3;
    struct landlock_path_beneath_attr pb = { .allowed_access = w, .parent_fd = dfd };
    if (ll_add(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) return -4;
    close(dfd);
    if (ll_restrict(rs, 0)) return -5;
    close(rs);
    return 0;
}

// ---- minimal raw io_uring openat (no liburing), same shape as iouring_probe.c ---------------
static int ring_openat(const char *path){
    struct io_uring_params p; memset(&p, 0, sizeof p);
    int rfd = (int)syscall(__NR_io_uring_setup, 8, &p);
    if (rfd < 0) return -errno;
    size_t sqring = p.sq_off.array + p.sq_entries*sizeof(unsigned);
    size_t cqring = p.cq_off.cqes  + p.cq_entries*sizeof(struct io_uring_cqe);
    if (p.features & IORING_FEAT_SINGLE_MMAP) sqring = cqring = (sqring>cqring?sqring:cqring);
    void *sq = mmap(NULL, sqring, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, rfd, IORING_OFF_SQ_RING);
    if (sq == MAP_FAILED) return -errno;
    void *cq = sq;
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)){
        cq = mmap(NULL, cqring, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, rfd, IORING_OFF_CQ_RING);
        if (cq == MAP_FAILED) return -errno;
    }
    struct io_uring_sqe *sqes = mmap(NULL, p.sq_entries*sizeof(struct io_uring_sqe),
        PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, rfd, IORING_OFF_SQES);
    if (sqes == MAP_FAILED) return -errno;
    unsigned *sq_tail = (unsigned*)((char*)sq + p.sq_off.tail);
    unsigned *sq_mask = (unsigned*)((char*)sq + p.sq_off.ring_mask);
    unsigned *sq_arr  = (unsigned*)((char*)sq + p.sq_off.array);
    unsigned *cq_head = (unsigned*)((char*)cq + p.cq_off.head);
    unsigned *cq_mask = (unsigned*)((char*)cq + p.cq_off.ring_mask);
    struct io_uring_cqe *cqes = (struct io_uring_cqe*)((char*)cq + p.cq_off.cqes);
    unsigned tail = atomic_load_explicit((_Atomic unsigned*)sq_tail, memory_order_relaxed);
    unsigned idx = tail & *sq_mask;
    struct io_uring_sqe *s = &sqes[idx]; memset(s, 0, sizeof *s);
    s->opcode = IORING_OP_OPENAT; s->fd = AT_FDCWD; s->addr = (uint64_t)(uintptr_t)path;
    s->open_flags = O_WRONLY|O_CREAT|O_TRUNC; s->len = 0644; s->user_data = 1;
    sq_arr[idx] = idx;
    atomic_store_explicit((_Atomic unsigned*)sq_tail, tail+1, memory_order_release);
    if (syscall(__NR_io_uring_enter, rfd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0){ close(rfd); return -errno; }
    unsigned ch = atomic_load_explicit((_Atomic unsigned*)cq_head, memory_order_relaxed);
    int res = cqes[ch & *cq_mask].res;
    close(rfd);
    return res;
}

static const char *say(int rc){ // rc: fd/0 on success, -errno on failure
    static char b[96];
    if (rc >= 0) return "SUCCEEDED";
    snprintf(b, sizeof b, "denied(%s)", strerror(-rc));
    return b;
}

// run one attack in a child so a denial/kill cannot abort the sweep; return child status word.
static void run(const char *label, const char *invariant, int (*fn)(void*), void *arg){
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0){ int rc = fn(arg); printf("  [%s] %-22s -> %s\n", invariant, label, say(rc)); fflush(NULL); _exit(0); }
    int st; waitpid(pid, &st, 0);
}

struct paths { const char *scratch; const char *evil; const char *preopen; int preopen_fd; };

static int atk_write_outside(void *a){ struct paths *p=a;
    int fd = openat(AT_FDCWD, p->evil, O_WRONLY|O_CREAT|O_TRUNC, 0644); if(fd>=0){close(fd);return fd;} return -errno; }
static int atk_creat_alias(void *a){ struct paths *p=a;
    int fd = creat(p->evil, 0644); if(fd>=0){close(fd);return fd;} return -errno; }
static int atk_open_alias(void *a){ struct paths *p=a;
    int fd = open(p->evil, O_WRONLY|O_CREAT|O_TRUNC, 0644); if(fd>=0){close(fd);return fd;} return -errno; }
static int atk_iouring(void *a){ struct paths *p=a; return ring_openat(p->evil); }
static int atk_write_inside(void *a){ struct paths *p=a; char b[512];
    snprintf(b,sizeof b,"%s/allowed.txt",p->scratch);
    int fd=open(b,O_WRONLY|O_CREAT|O_TRUNC,0644); if(fd>=0){close(fd);return fd;} return -errno; }
static int atk_preopen_fd(void *a){ struct paths *p=a;   // the known discipline requirement
    if(p->preopen_fd<0) return -EBADF;
    ssize_t n=write(p->preopen_fd,"leaked\n",7); return n>=0 ? 0 : -errno; }
static int atk_execve(void *a){ (void)a; char *const av[]={"/bin/true",NULL};
    execve("/bin/true",av,NULL); return -errno; }
static int atk_tcp(void *a){ (void)a; int s=socket(AF_INET,SOCK_STREAM,0); if(s<0)return -errno;
    struct sockaddr_in sa={.sin_family=AF_INET,.sin_port=htons(53)}; inet_pton(AF_INET,"8.8.8.8",&sa.sin_addr);
    int r=connect(s,(void*)&sa,sizeof sa); close(s); return r==0?0:-errno; }
static int atk_udp(void *a){ (void)a; int s=socket(AF_INET,SOCK_DGRAM,0); if(s<0)return -errno;
    struct sockaddr_in sa={.sin_family=AF_INET,.sin_port=htons(53)}; inet_pton(AF_INET,"8.8.8.8",&sa.sin_addr);
    ssize_t r=sendto(s,"x",1,0,(void*)&sa,sizeof sa); close(s); return r>=0?0:-errno; }
static int atk_raw(void *a){ (void)a; int s=socket(AF_INET,SOCK_RAW,IPPROTO_RAW); if(s<0)return -errno;
    struct sockaddr_in sa={.sin_family=AF_INET}; inet_pton(AF_INET,"8.8.8.8",&sa.sin_addr);
    ssize_t r=sendto(s,"x",1,0,(void*)&sa,sizeof sa); close(s); return r>=0?0:-errno; }

int main(int argc, char **argv){
    if (argc < 4){ fprintf(stderr,"usage: unshare -rn %s <scratch> <evil_path> <preopen_path>\n",argv[0]); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct paths P = { .scratch=argv[1], .evil=argv[2], .preopen=argv[3], .preopen_fd=-1 };
    unlink(P.evil);   // FS oracle for the evil path starts empty

    // A descriptor opened on a SEPARATE sentinel path (outside scratch) BEFORE the sandbox is
    // applied -- the Part II pre-open hole, carried in to test whether the composition still
    // admits it (it does; that is the discipline requirement the supervisor must honour, not a
    // Landlock defect). Kept open, not unlinked, so its oracle is unambiguous.
    P.preopen_fd = open(P.preopen, O_WRONLY|O_CREAT|O_TRUNC, 0644);

    // Apply the sandbox to ourselves, in order.
    int l = install_landlock(P.scratch);
    int s = install_exec_deny();
    printf("SANDBOX landlock=%s seccomp=%s netns=%s\n",
           l==0?"on":"FAILED", s==0?"on":"FAILED",
           "caller(unshare -rn)");
    if (l!=0){ fprintf(stderr,"landlock setup rc=%d %s\n",l,strerror(errno)); return 3; }
    if (s!=0){ fprintf(stderr,"seccomp setup rc=%d %s\n",s,strerror(errno)); return 4; }

    printf("I1 filesystem  (Landlock allowlist beneath scratch; evil path is outside)\n");
    run("openat write",   "I1", atk_write_outside, &P);
    run("open alias",     "I1", atk_open_alias,    &P);
    run("creat alias",    "I1", atk_creat_alias,   &P);
    run("io_uring openat", "I1", atk_iouring,       &P);
    run("write inside",   "I1", atk_write_inside,  &P);   // control: allowlisted write must SUCCEED
    run("pre-open fd write","I1", atk_preopen_fd,  &P);   // known hole: expect SUCCEEDED
    printf("I2 execution   (seccomp deny execve/execveat)\n");
    run("execve /bin/true","I2", atk_execve,        &P);
    printf("I3 network     (empty netns, no route off host)\n");
    run("tcp connect",    "I3", atk_tcp,           &P);
    run("udp sendto",     "I3", atk_udp,           &P);
    run("raw sendto",     "I3", atk_raw,           &P);

    // FS ground truth. The evil path must NOT exist (every I1 open/alias/ring attempt was denied);
    // the pre-open sentinel WILL carry the leaked bytes (that path had a descriptor from before the
    // domain), which is the discipline caveat stated as a measurement rather than asserted.
    struct stat st;
    if (P.preopen_fd>=0) close(P.preopen_fd);
    printf("ORACLE evil_path_exists=%s preopen_sentinel_leaked=%s\n",
           stat(P.evil,&st)==0?"YES":"no",
           (stat(P.preopen,&st)==0 && st.st_size>0)?"YES":"no");
    return 0;
}
