// egress_tap.c -- the wire witness for the egress oracle.
//
// The sink proves a datagram was delivered to a socket we control. That is the arrival
// claim, and it is the strong one. It is not the only thing worth knowing: a hand-built raw
// packet can cross the wire and still miss the socket if a header field is wrong, and in
// that case "nothing arrived" and "nothing was sent" are very different facts about the
// control under test. This is the second, independent witness.
//
// tcpdump cannot be used here. It drops privileges unconditionally, and setgroups(2) is
// denied inside an unprivileged user namespace, so it exits before it captures a frame:
//
//     tcpdump: Couldn't change to 'tcpdump' uid=107 gid=113: Operation not permitted
//
// AF_PACKET itself works fine with the CAP_NET_RAW the user namespace grants, so the tap is
// twenty lines of socket code rather than a dependency the reproducer would have to satisfy.
//
// Build: gcc -O2 egress_tap.c -o egress_tap
// Usage: egress_tap <ifname>
//        one "WIRE <len> <printable>" line per frame, unbuffered.
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

static volatile sig_atomic_t g_stop = 0;
static void on_term(int s){ (void)s; g_stop = 1; }

int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr, "usage: %s <ifname>\n", argv[0]); return 2; }

    signal(SIGTERM, on_term);
    signal(SIGINT,  on_term);

    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0){ perror("AF_PACKET"); return 3; }

    unsigned idx = if_nametoindex(argv[1]);
    if (!idx){ perror("if_nametoindex"); return 3; }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)idx;
    if (bind(s, (struct sockaddr *)&sll, sizeof sll)){ perror("bind"); return 3; }

    printf("TAP_READY %s\n", argv[1]);
    fflush(stdout);

    unsigned char buf[65536];
    char out[65536];
    while (!g_stop){
        ssize_t n = recv(s, buf, sizeof buf, 0);
        if (n < 0){ if (errno == EINTR) continue; break; }
        // Render the whole frame as one printable line. Non-printable bytes become dots, so
        // an ASCII sentinel anywhere in the payload stays contiguous and greppable -- which
        // is the thing tcpdump's wrapped -A output would have made fiddly.
        ssize_t j = 0;
        for (ssize_t i = 0; i < n && j < (ssize_t)sizeof out - 1; i++)
            out[j++] = (buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.';
        out[j] = 0;
        printf("WIRE %zd %s\n", n, out);
        fflush(stdout);
    }
    close(s);
    printf("TAP_DONE\n");
    fflush(stdout);
    return 0;
}
