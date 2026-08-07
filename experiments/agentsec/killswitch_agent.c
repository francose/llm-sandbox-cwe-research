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

// A short-lived grandchild: ~20 ms of work, then exit. This is the concurrent fork that a
// PID-enumeration sweep races -- a grandchild spawned after the snapshot is not in the kill list.
static void grandchild(void){
    alarm(25);                                   // self-terminate if ever orphaned (safety net)
    for (int k = 0; k < 20; k++){
        atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
        usleep(1000);
    }
    _exit(0);
}

// A persistent worker: loops forever, and every ~8 ms forks a short-lived grandchild. Many
// independent workers forking continuously means killing the supervisor does not stop the churn --
// each surviving worker keeps spawning fresh PIDs until it is individually killed.
static void worker(void){
    alarm(25);                                   // safety net: no worker outlives the experiment
    for (int n = 0; ; n++){
        atomic_fetch_add_explicit(counter, 1, memory_order_relaxed);
        usleep(1000);
        if (n % 8 == 0){
            pid_t g = fork();
            if (g == 0) grandchild();
        }
        while (waitpid(-1, NULL, WNOHANG) > 0){}  // reap exited grandchildren, no zombies
    }
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

    alarm(30);                                   // supervisor self-terminates if orphaned
    for (int i = 0; i < K; i++){
        pid_t p = fork();
        if (p == 0) worker();
    }
    for (;;){ pause(); }                          // hold the tree open until killed
    return 0;
}
