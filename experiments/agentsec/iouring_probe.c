// iouring_probe.c -- does an asynchronous file open reach the control?
//
// Section "Coverage is incomplete before any race" asserts that an agent can submit openat,
// write, connect and unlink as io_uring ring operations "that never reach the syscall-entry
// filter". That was read off the ABI, not measured. This probe measures it, and asks the same
// question of the Landlock successor of Part II, where the answer should differ: Landlock hooks
// the LSM, not the syscall entry, and io_uring work carries the submitting task's credentials.
//
// Two paths to the same effect, run back to back in one process:
//   direct : openat(AT_FDCWD, path, O_WRONLY|O_CREAT, 0644)
//   ring   : IORING_OP_OPENAT on the same path through an established ring
//
// The oracle is the errno / cqe->res the kernel returns, plus whether the file exists after.
// Raw io_uring, no liburing, so this builds with plain gcc like everything else here.
//
// Build: gcc -O2 iouring_probe.c -o iouring_probe
// Usage: iouring_probe <path>
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#endif

static int io_setup(unsigned e, struct io_uring_params *p){
    return (int)syscall(__NR_io_uring_setup, e, p);
}
static int io_enter(int fd, unsigned to_submit, unsigned min_complete, unsigned flags){
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
}

struct ring {
    int fd;
    unsigned *sq_head, *sq_tail, *sq_mask, *sq_array;
    unsigned *cq_head, *cq_tail, *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
};

static int ring_init(struct ring *r){
    struct io_uring_params p;
    memset(&p, 0, sizeof p);
    r->fd = io_setup(8, &p);
    if (r->fd < 0) return -1;

    // With IORING_FEAT_SINGLE_MMAP the SQ and CQ rings share one mapping; without it the CQ
    // ring needs its own. Handle both so the probe is not tied to one kernel.
    size_t sqring = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cqring = p.cq_off.cqes  + p.cq_entries * sizeof(struct io_uring_cqe);
    if (p.features & IORING_FEAT_SINGLE_MMAP)
        sqring = cqring = (sqring > cqring ? sqring : cqring);

    void *sq = mmap(NULL, sqring, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                    r->fd, IORING_OFF_SQ_RING);
    if (sq == MAP_FAILED) return -2;
    void *cq = sq;
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)){
        cq = mmap(NULL, cqring, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                  r->fd, IORING_OFF_CQ_RING);
        if (cq == MAP_FAILED) return -3;
    }
    r->sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
                   PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) return -4;

    r->sq_head  = (unsigned *)((char *)sq + p.sq_off.head);
    r->sq_tail  = (unsigned *)((char *)sq + p.sq_off.tail);
    r->sq_mask  = (unsigned *)((char *)sq + p.sq_off.ring_mask);
    r->sq_array = (unsigned *)((char *)sq + p.sq_off.array);
    r->cq_head  = (unsigned *)((char *)cq + p.cq_off.head);
    r->cq_tail  = (unsigned *)((char *)cq + p.cq_off.tail);
    r->cq_mask  = (unsigned *)((char *)cq + p.cq_off.ring_mask);
    r->cqes     = (struct io_uring_cqe *)((char *)cq + p.cq_off.cqes);
    return 0;
}

// Submit one openat through the ring and return the kernel's result (fd, or -errno).
static int ring_openat(struct ring *r, const char *path){
    unsigned tail = atomic_load_explicit((_Atomic unsigned *)r->sq_tail, memory_order_relaxed);
    unsigned idx  = tail & *r->sq_mask;
    struct io_uring_sqe *s = &r->sqes[idx];
    memset(s, 0, sizeof *s);
    s->opcode     = IORING_OP_OPENAT;
    s->fd         = AT_FDCWD;
    s->addr       = (uint64_t)(uintptr_t)path;
    s->open_flags = O_WRONLY | O_CREAT | O_TRUNC;
    s->len        = 0644;                       // mode, for O_CREAT
    s->user_data  = 1;
    r->sq_array[idx] = idx;
    atomic_store_explicit((_Atomic unsigned *)r->sq_tail, tail + 1, memory_order_release);

    if (io_enter(r->fd, 1, 1, IORING_ENTER_GETEVENTS) < 0) return -errno;

    unsigned chead = atomic_load_explicit((_Atomic unsigned *)r->cq_head, memory_order_relaxed);
    struct io_uring_cqe *c = &r->cqes[chead & *r->cq_mask];
    int res = c->res;
    atomic_store_explicit((_Atomic unsigned *)r->cq_head, chead + 1, memory_order_release);
    return res;
}

static const char *verdict(int res){
    static char b[80];
    if (res >= 0) return "OPENED";
    snprintf(b, sizeof b, "denied (%s)", strerror(-res));
    return b;
}

int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr, "usage: %s <path>\n", argv[0]); return 2; }
    const char *path = argv[1];
    setvbuf(stdout, NULL, _IOLBF, 0);

    // 1. the ordinary syscall, as a control.
    unlink(path);
    int d = openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    printf("direct=%s", d >= 0 ? "OPENED" : verdict(-errno));
    if (d >= 0) close(d);

    // 2. the same open, submitted through an established ring.
    unlink(path);
    struct ring r;
    int rc = ring_init(&r);
    if (rc < 0){
        printf(" ring=unavailable(setup rc=%d %s)\n", rc, strerror(errno));
        return 0;
    }
    int res = ring_openat(&r, path);
    printf(" ring=%s", verdict(res));
    if (res >= 0) close(res);

    // 3. the ground truth: did the file get created?
    struct stat st;
    printf(" file_exists=%s\n", stat(path, &st) == 0 ? "yes" : "no");
    close(r.fd);
    return 0;
}
