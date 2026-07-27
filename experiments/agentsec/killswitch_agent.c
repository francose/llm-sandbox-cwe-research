// killswitch_agent.c -- a bounded, churning process tree for the I4/I5 kill-switch test.
//
// A supervisor keeps K workers alive; each worker appends to a shared counter for a fixed span,
// then exits, and the supervisor respawns it. The population stays ~K (never a real fork bomb --
// safe to run on a workstation) but the PIDs churn continuously, which is exactly the condition a
// PID-enumeration kill races: a snapshot of cgroup.procs is stale the moment it is taken, and any
// worker respawned after the snapshot survives the sweep. cgroup.kill has no such gap.
//
// The shared counter is the "work completed" signal: comparing it at trigger time and after
// quiescence gives the side effects that landed AFTER the kill was issued.
//
// Build: gcc -O2 killswitch_agent.c -o killswitch_agent
// Usage: killswitch_agent <counter_file> [K]
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdatomic.h>

static _Atomic long *counter;

static void worker(void){
    // ~300 ms of work, appending to the shared counter, then exit so the supervisor churns us.
    for (int n = 0; n < 300; n++){
        atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
        usleep(1000);
    }
    _exit(0);
}

int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr, "usage: %s <counter_file> [K]\n", argv[0]); return 2; }
    int K = (argc > 2) ? atoi(argv[2]) : 30;
    if (K < 1 || K > 200) K = 30;

    int cf = open(argv[1], O_RDWR|O_CREAT, 0644);
    if (cf < 0){ perror("open counter"); return 3; }
    if (ftruncate(cf, sizeof(long))) { perror("ftruncate"); return 3; }
    counter = mmap(NULL, sizeof(long), PROT_READ|PROT_WRITE, MAP_SHARED, cf, 0);
    if (counter == MAP_FAILED){ perror("mmap"); return 3; }

    for (int i = 0; i < K; i++){
        pid_t p = fork();
        if (p == 0) worker();
    }
    // Supervisor: respawn any worker that exits, forever. This churn defeats a PID snapshot.
    for (;;){
        int st; pid_t d = wait(&st);
        if (d < 0 && errno == ECHILD){ sleep(1); }   // no children yet; stay alive
        pid_t p = fork();
        if (p == 0) worker();
    }
    return 0;
}
