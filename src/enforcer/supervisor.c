// supervisor.c -- a seccomp user-notification enforcer.
//
// The idea is simple: put the tool allow-list where it actually binds, in the kernel,
// instead of in the agent framework where it is only advice. The supervisor installs a
// seccomp filter that turns every execve/execveat and every connect() into a notification,
// forks a child that tries to run various binaries and reach the engine socket, and decides
// allow or deny for each one before it happens.
//
//   - execve/execveat: read the program path out of the child's memory and check it against
//     the approved list. Approved ones run; the rest get EPERM and never start. This is the
//     "run a different binary" path.
//   - connect(): read the address out of the child's memory. A connect to the engine socket
//     (docker.sock / podman.sock) is denied; other connects go through. This is the
//     Docker-out-of-Docker path, which is a socket call rather than an execve, so anything
//     that only watches execve misses it.
//
// You need both, or the child just goes around the exec check through the socket. It still
// cannot run under a privileged container, where seccomp is turned off.
//
// Build:  gcc -O2 -o supervisor supervisor.c -lseccomp
// Run:    ./supervisor <events.jsonl>   (needs CAP_SYS_ADMIN; a rootless userns works: unshare -Ur)
//
// Author: sadik-erisen.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include <linux/seccomp.h>

extern char **environ;

// The framework-layer allow-list, now enforced at the syscall layer.
static const char *APPROVED[] = { "echo", "id", "true", "cat", NULL };

// Agent's exec attempts, in order. A realistic set of binaries a tool-enabled agent
// reaches for, each standing in for an acquisition path an executor would restrict:
//   echo/id/cat   approved (baseline: they run)
//   bash/sh       interactive shell / arbitrary command
//   docker        drive the engine directly
//   curl/wget     fetch-and-exec a payload
//   nc            reverse shell / raw socket
//   python3       reimplement a tool in an approved interpreter
//   git           pull code, then run it
//   unzip         the original stand-in, now one of many
//   busybox       multi-tool carrier (one binary, many applets)
//   chmod         make a dropped payload executable
//   mount         filesystem manipulation
static const char *ATTEMPTS[] = {
    "/bin/echo",        // approved
    "/usr/bin/id",      // approved
    "/bin/cat",         // approved
    "/bin/bash",        // denied
    "/bin/sh",          // denied
    "/usr/bin/docker",  // denied
    "/usr/bin/curl",    // denied
    "/usr/bin/wget",    // denied
    "/bin/nc",          // denied
    "/usr/bin/python3", // denied
    "/usr/bin/git",     // denied
    "/usr/bin/unzip",   // denied
    "/bin/busybox",     // denied
    "/bin/chmod",       // denied
    "/bin/mount",       // denied
    NULL
};
#define STOP_MARKER "/__STOP__"

static int approved(const char *base) {
    for (int i = 0; APPROVED[i]; i++)
        if (strcmp(base, APPROVED[i]) == 0) return 1;
    return 0;
}

// A connect() to any of these is the DooD engine-socket escalation.
static int is_engine_socket(const char *path) {
    size_t n = strlen(path);
    if (n >= 11 && strcmp(path + n - 11, "docker.sock") == 0) return 1;
    if (n >= 11 && strcmp(path + n - 11, "podman.sock") == 0) return 1;
    return 0;
}

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_REALTIME, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

// Read raw bytes from the target process memory at the given address.
static ssize_t read_mem(pid_t pid, unsigned long long addr, char *out, size_t n) {
    char mem[64]; snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);
    int fd = open(mem, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = pread(fd, out, n, (off_t)addr);
    close(fd);
    return r;
}

// Read a NUL-terminated path from the target process memory.
static void read_path(pid_t pid, unsigned long long addr, char *out, size_t n) {
    out[0] = '\0';
    ssize_t r = read_mem(pid, addr, out, n - 1);
    if (r > 0) out[r] = '\0';
    out[n - 1] = '\0';
}

static void try_exec(const char *bin) {
    pid_t g = fork();
    if (g == 0) {
        char *av[] = { (char *)bin, (char *)"[agent-action]", NULL };
        execve(bin, av, environ);
        // Only reached if the syscall was allowed-but-missing, or denied (EPERM).
        fprintf(stderr, "  agent: exec    %-22s -> blocked/failed (errno=%d %s)\n",
                bin, errno, strerror(errno));
        _exit(1);
    }
    int st; waitpid(g, &st, 0);
}

static void try_connect(const char *path) {
    pid_t g = fork();
    if (g == 0) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un sa; memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
        int rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));
        fprintf(stderr, "  agent: connect %-22s -> %s (errno=%d %s)\n",
                path, rc == 0 ? "OK" : "blocked/failed", errno, strerror(errno));
        if (s >= 0) close(s);
        _exit(rc == 0 ? 0 : 1);
    }
    int st; waitpid(g, &st, 0);
}

static void run_agent(void) {
    for (int i = 0; ATTEMPTS[i]; i++) try_exec(ATTEMPTS[i]);
    // The socket path the exec-only monitor used to miss: engine socket must be denied,
    // an unrelated unix path must still be allowed (proving the gate is selective).
    try_connect("/var/run/docker.sock");
    try_connect("/tmp/benign.sock");
    // Sentinel so the supervisor knows the run is done.
    char *av[] = { (char *)STOP_MARKER, NULL };
    execve(STOP_MARKER, av, environ);
    _exit(0);
}

int main(int argc, char **argv) {
    const char *logpath = (argc > 1) ? argv[1] : NULL;
    FILE *log = logpath ? fopen(logpath, "w") : NULL;

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { fprintf(stderr, "seccomp_init failed\n"); return 1; }
    seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(connect), 0);
    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "seccomp_load failed (need CAP_SYS_ADMIN / --privileged): %s\n", strerror(errno));
        return 1;
    }

    int nfd = seccomp_notify_fd(ctx);
    if (nfd < 0) { fprintf(stderr, "no notify fd\n"); return 1; }

    pid_t agent = fork();
    if (agent == 0) { run_agent(); _exit(0); }

    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    seccomp_notify_alloc(&req, &resp);

    fprintf(stderr, "[supervisor] watching execve + connect; approved tools continue, "
                    "non-approved binaries and the engine socket get EPERM\n");
    for (;;) {
        memset(req, 0, sizeof(*req));
        if (seccomp_notify_receive(nfd, req) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // ---- connect(): gate the engine-socket path ----
        if (req->data.nr == __NR_connect) {
            struct sockaddr_un sa; memset(&sa, 0, sizeof(sa));
            read_mem(req->pid, req->data.args[1], (char *)&sa, sizeof(sa));
            if (seccomp_notify_id_valid(nfd, req->id) < 0) continue;

            char sun[128]; sun[0] = '\0';
            int deny = 0;
            if (sa.sun_family == AF_UNIX && sa.sun_path[0] != '\0') {
                snprintf(sun, sizeof(sun), "%s", sa.sun_path);
                deny = is_engine_socket(sun);
            }
            resp->id = req->id; resp->val = 0;
            if (deny) { resp->error = -EPERM; resp->flags = 0; }
            else      { resp->error = 0; resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; }
            seccomp_notify_respond(nfd, resp);

            fprintf(stderr, "[supervisor] connect %-18s pid=%d -> %s\n",
                    sun[0] ? sun : "(non-unix)", req->pid, deny ? "DENY" : "ALLOW");
            if (log) {
                fprintf(log, "{\"ts\": %.6f, \"pid\": %d, \"syscall\": \"connect\", "
                             "\"path\": \"%s\", \"decision\": \"%s\"}\n",
                        now_s(), req->pid, sun, deny ? "DENY" : "ALLOW");
                fflush(log);
            }
            continue;
        }

        // ---- execve/execveat: gate the tool name ----
        // execve: pathname is arg0. execveat: dirfd is arg0, pathname is arg1.
        unsigned long long pathaddr =
            (req->data.nr == __NR_execveat) ? req->data.args[1] : req->data.args[0];
        char path[512];
        read_path(req->pid, pathaddr, path, sizeof(path));
        if (seccomp_notify_id_valid(nfd, req->id) < 0) continue;

        const char *slash = strrchr(path, '/');
        const char *base = slash ? slash + 1 : path;

        if (strcmp(path, STOP_MARKER) == 0) {
            resp->id = req->id; resp->error = -EPERM; resp->val = 0; resp->flags = 0;
            seccomp_notify_respond(nfd, resp);
            break;
        }

        int allow = approved(base);
        resp->id = req->id; resp->val = 0;
        if (allow) { resp->error = 0; resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; }
        else       { resp->error = -EPERM; resp->flags = 0; }
        seccomp_notify_respond(nfd, resp);

        fprintf(stderr, "[supervisor] execve %-18s pid=%d -> %s\n",
                path, req->pid, allow ? "ALLOW" : "DENY");
        if (log) {
            fprintf(log, "{\"ts\": %.6f, \"pid\": %d, \"syscall\": \"execve\", "
                         "\"path\": \"%s\", \"tool\": \"%s\", \"decision\": \"%s\"}\n",
                    now_s(), req->pid, path, base, allow ? "ALLOW" : "DENY");
            fflush(log);
        }
    }

    seccomp_notify_free(req, resp);
    int st; waitpid(agent, &st, 0);
    if (log) fclose(log);
    fprintf(stderr, "[supervisor] done\n");
    return 0;
}
