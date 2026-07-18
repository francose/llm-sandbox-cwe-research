#define _GNU_SOURCE
#include <seccomp.h>
#include <stdio.h>
static void install_gate(void){
    scmp_filter_ctx c = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(c, SCMP_ACT_ERRNO(1), SCMP_SYS(execve), 0);   // block exec (system/sh/curl)
    seccomp_rule_add(c, SCMP_ACT_ERRNO(1), SCMP_SYS(execveat), 0);
    seccomp_rule_add(c, SCMP_ACT_ERRNO(1), SCMP_SYS(connect), 0);  // block network exfil
    if (seccomp_load(c)!=0) fprintf(stderr,"GATE_LOAD_FAIL\n");
    seccomp_release(c);
}
