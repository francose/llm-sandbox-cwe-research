// EXP-12 false-positive probe: run a corpus of write paths through the --persist rootful gate and
// record, per path, whether the gate ALLOWED or DENIED the openat. No race here -- this measures the
// gate's SELECTIVITY (does it wrongly block benign work?), the other half of the confusion matrix
// that EXP-11 (false negatives) and the injection experiments (true positives) never touched.
//
// Reads newline-separated paths from the file named in argv[1]; for each, attempts a writeish openat
// and prints "ALLOW\t<path>" or "DENY\t<path>". The harness joins these to ground-truth labels.
//
// Build: gcc -O2 fp_probe.c -o fp_probe
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <pathlist>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror("fopen"); return 3; }
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
        if (!n) continue;
        long fd = syscall(SYS_openat, AT_FDCWD, line, O_WRONLY | O_CREAT, 0644);
        if (fd < 0) { printf("DENY\t%s\n", line); }
        else        { printf("ALLOW\t%s\n", line); close((int)fd); }
        fflush(stdout);
    }
    fclose(f);
    return 0;
}
