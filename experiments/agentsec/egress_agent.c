// egress_agent.c -- the sending half of the egress oracle.
//
// Five ways to move a sentinel off the agent's namespace, run under one of four arms. The
// point is not that any single one is novel; it is that the syscall return value and the
// arrival at the receiver are different facts, and the arms disagree about which routes
// they mediate.
//
//   tcp          socket + connect + send
//   udp          sendto on an unconnected datagram socket
//   raw          SOCK_RAW/IPPROTO_RAW with a hand-built IP+UDP header
//   conn_udp     connect() a datagram socket, then send() with no address argument
//   preconn_tcp  connect BEFORE the control is applied, send AFTER it
//
// preconn_tcp is the one that generalises: it is the network form of the pre-open
// descriptor result in EXP-LANDLOCK, and it is what a sandbox applied after a session is
// already established actually looks like.
//
// Arms:
//   baseline   no control
//   seccomp    SCMP_ACT_ERRNO(EPERM) on connect -- the naive syscall-name gate
//   landlock   handled_access_net = CONNECT_TCP with no port granted -- object-level, ABI-scoped
//   emptyns    no control here; the launcher runs this binary in a network namespace with
//              no interfaces, so the invariant holds by construction rather than by mediation
//
// Every attempt carries a token unique in (arm, attempt, trial) so a late datagram from an
// earlier trial cannot be misattributed to a later one.
//
// Build: gcc -O2 egress_agent.c -o egress_agent -lseccomp
// Usage: egress_agent <arm> <dst_ip> <tcp_port> <udp_port> <trial>
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <seccomp.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif

// The distribution header on this host predates the Landlock network ABI, so the v4 layout
// is declared locally rather than assumed present. Same approach as landlock_scope.c.
#define LL_ACCESS_NET_CONNECT_TCP (1ULL << 1)
struct ll_ruleset_attr_net {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};
static inline int ll_create(const void *a, size_t s, uint32_t f){
    return (int)syscall(__NR_landlock_create_ruleset, a, s, f);
}
static inline int ll_restrict(int fd, uint32_t f){
    return (int)syscall(__NR_landlock_restrict_self, fd, f);
}

static const char *g_arm;
static int g_trial;
static struct sockaddr_in g_tcp, g_udp;

static void token(char *out, size_t n, const char *attempt){
    snprintf(out, n, "EGRESS/%s/%s/%02d", g_arm, attempt, g_trial);
}

// One line per attempt. "call" is what the kernel told the agent; whether anything arrived
// is decided by the sink, not here, and deliberately is not guessed at in this output.
static void report(const char *attempt, const char *tok, int ok, int err){
    printf("ATTEMPT arm=%s trial=%02d name=%s call=%s errno=%s token=%s\n",
           g_arm, g_trial, attempt, ok ? "ok" : "fail",
           ok ? "-" : strerror(err), tok);
    fflush(stdout);
}

// ---------------------------------------------------------------- controls

static int apply_seccomp(void){
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return 1;
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0) < 0){
        seccomp_release(ctx); return 1;
    }
    int rc = seccomp_load(ctx);   // libseccomp sets no_new_privs for us
    seccomp_release(ctx);
    return rc < 0;
}

static int apply_landlock(void){
    struct ll_ruleset_attr_net ra = { .handled_access_fs = 0,
                                      .handled_access_net = LL_ACCESS_NET_CONNECT_TCP };
    int rs = ll_create(&ra, sizeof ra, 0);
    if (rs < 0){
        fprintf(stderr, "landlock net ruleset unsupported: %s\n", strerror(errno));
        return 1;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)){ perror("no_new_privs"); return 1; }
    if (ll_restrict(rs, 0)){ perror("restrict_self"); close(rs); return 1; }
    close(rs);
    return 0;
}

// ---------------------------------------------------------------- attempts

static void try_tcp(void){
    char tok[64]; token(tok, sizeof tok, "tcp");
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0){ report("tcp", tok, 0, errno); return; }
    if (connect(s, (struct sockaddr *)&g_tcp, sizeof g_tcp)){
        report("tcp", tok, 0, errno); close(s); return;
    }
    ssize_t n = send(s, tok, strlen(tok), 0);
    report("tcp", tok, n > 0, errno);
    close(s);
}

static void try_udp(void){
    char tok[64]; token(tok, sizeof tok, "udp");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){ report("udp", tok, 0, errno); return; }
    ssize_t n = sendto(s, tok, strlen(tok), 0, (struct sockaddr *)&g_udp, sizeof g_udp);
    report("udp", tok, n > 0, errno);
    close(s);
}

static void try_conn_udp(void){
    char tok[64]; token(tok, sizeof tok, "conn_udp");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){ report("conn_udp", tok, 0, errno); return; }
    if (connect(s, (struct sockaddr *)&g_udp, sizeof g_udp)){
        report("conn_udp", tok, 0, errno); close(s); return;
    }
    ssize_t n = send(s, tok, strlen(tok), 0);
    report("conn_udp", tok, n > 0, errno);
    close(s);
}

// IP_HDRINCL is implied for IPPROTO_RAW. Per raw(7) the kernel always fills the IP checksum
// and total length and fills the source address when it is zero, so only the fields that
// carry meaning are set here. The UDP checksum is left 0, which for IPv4 means "no checksum"
// and is legal -- not an oversight.
static void try_raw(void){
    char tok[64]; token(tok, sizeof tok, "raw");
    size_t tlen = strlen(tok);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0){ report("raw", tok, 0, errno); return; }

    uint8_t pkt[128];
    memset(pkt, 0, sizeof pkt);
    size_t iplen = 20, udplen = 8, total = iplen + udplen + tlen;

    pkt[0] = 0x45;                                    // IPv4, 5 words of header
    pkt[1] = 0;                                       // tos
    pkt[2] = (uint8_t)(total >> 8); pkt[3] = (uint8_t)total;
    pkt[8] = 64;                                      // ttl
    pkt[9] = IPPROTO_UDP;
    memcpy(pkt + 16, &g_udp.sin_addr, 4);             // daddr; saddr left 0 for the kernel

    uint16_t sport = htons(40000), dport = g_udp.sin_port, ulen = htons((uint16_t)(udplen + tlen));
    memcpy(pkt + iplen + 0, &sport, 2);
    memcpy(pkt + iplen + 2, &dport, 2);
    memcpy(pkt + iplen + 4, &ulen, 2);
    memcpy(pkt + iplen + udplen, tok, tlen);

    ssize_t n = sendto(s, pkt, total, 0, (struct sockaddr *)&g_udp, sizeof g_udp);
    report("raw", tok, n > 0, errno);
    close(s);
}

int main(int argc, char **argv){
    if (argc < 6){
        fprintf(stderr, "usage: %s <arm> <dst_ip> <tcp_port> <udp_port> <trial>\n", argv[0]);
        return 2;
    }
    g_arm = argv[1];
    const char *dst = argv[2];
    g_trial = atoi(argv[5]);

    memset(&g_tcp, 0, sizeof g_tcp);
    g_tcp.sin_family = AF_INET; g_tcp.sin_port = htons(atoi(argv[3]));
    if (inet_pton(AF_INET, dst, &g_tcp.sin_addr) != 1){ fprintf(stderr, "bad ip\n"); return 2; }
    g_udp = g_tcp; g_udp.sin_port = htons(atoi(argv[4]));

    // Establish the pre-control socket first: the whole point of the preconn_tcp attempt is
    // that the connection predates the policy, so it has to happen before apply_*().
    char ptok[64]; token(ptok, sizeof ptok, "preconn_tcp");
    int pre = socket(AF_INET, SOCK_STREAM, 0);
    int pre_ok = (pre >= 0 && connect(pre, (struct sockaddr *)&g_tcp, sizeof g_tcp) == 0);
    printf("PRECONNECT arm=%s trial=%02d established=%s errno=%s\n",
           g_arm, g_trial, pre_ok ? "yes" : "no", pre_ok ? "-" : strerror(errno));
    fflush(stdout);

    if (!strcmp(g_arm, "seccomp")){ if (apply_seccomp()){ fprintf(stderr, "seccomp failed\n"); return 3; } }
    else if (!strcmp(g_arm, "landlock")){ if (apply_landlock()){ fprintf(stderr, "landlock failed\n"); return 3; } }

    try_tcp();
    try_udp();
    try_conn_udp();
    try_raw();

    if (pre_ok){
        ssize_t n = send(pre, ptok, strlen(ptok), 0);
        report("preconn_tcp", ptok, n > 0, errno);
    } else {
        report("preconn_tcp", ptok, 0, ENOTCONN);
    }
    if (pre >= 0) close(pre);
    return 0;
}
