// ioctl_decode.c -- why seccomp cannot meaningfully filter ioctl(2).
//
// An ioctl request number is a packed 32-bit word (asm-generic encoding): direction (2 bits),
// argument size (14 bits), a per-driver "type"/magic byte (8 bits), and a function number (8 bits),
// assembled by the _IO/_IOR/_IOW/_IOWR macros in <asm-generic/ioctl.h>. We take REAL request numbers
// straight from the system headers (no hand-typed constants) and decode each with the kernel's own
// _IOC_DIR/_IOC_TYPE/_IOC_NR/_IOC_SIZE macros. The point: even fully decoded, the request number tells
// a seccomp filter the operation class and the *size* of the argument -- never the argument's CONTENTS,
// and never which device instance is targeted. The third ioctl() argument is an opaque userspace
// pointer, and a seccomp BPF program can read only the scalar syscall args (seccomp_data); it cannot
// dereference that pointer. So a filter can at best allowlist request numbers per driver-magic.
//
//   Build: gcc -O2 ioctl_decode.c -o ioctl_decode ; Run: ./ioctl_decode
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ioctl.h>          // TIOCGWINSZ, TCGETS, FIONREAD (pulls asm-generic/ioctls.h)
#include <asm-generic/ioctl.h>  // _IOC_DIR/_IOC_TYPE/_IOC_NR/_IOC_SIZE and _IOC_{NONE,READ,WRITE}
#include <linux/if_tun.h>       // TUNSETIFF  (network TAP device)
#include <drm/drm.h>            // DRM_IOCTL_VERSION, DRM_IOCTL_MODE_MAP_DUMB (GPU)

static const char *dirstr(unsigned d){
    switch (d) {
        case _IOC_NONE:                return "NONE ";
        case _IOC_READ:                return "R    ";   // kernel writes -> user reads
        case _IOC_WRITE:               return "W    ";   // user writes -> kernel reads
        case _IOC_READ | _IOC_WRITE:   return "RW   ";
        default:                       return "?    ";
    }
}

static void decode(const char *name, unsigned long req, const char *argtype){
    printf("%-26s = 0x%08lx  dir=%s type='%c'(0x%02x) nr=%3u size=%4u  arg: %s\n",
           name, req,
           dirstr(_IOC_DIR(req)),
           (int)_IOC_TYPE(req), (unsigned)_IOC_TYPE(req),
           (unsigned)_IOC_NR(req), (unsigned)_IOC_SIZE(req),
           argtype);
}

int main(void){
    printf("ioctl request-number decode (asm-generic encoding). "
           "The 'arg' column is what seccomp CANNOT see -- an opaque userspace pointer.\n\n");
    decode("TIOCGWINSZ", TIOCGWINSZ,          "struct winsize *  (terminal size)");
    decode("TCGETS",     TCGETS,              "struct termios *  (terminal attrs)");
    decode("FIONREAD",   FIONREAD,            "int *             (bytes readable)");
    decode("TUNSETIFF",  TUNSETIFF,           "struct ifreq *    (TAP netdev config)");
    decode("DRM_IOCTL_VERSION",  DRM_IOCTL_VERSION,  "struct drm_version *   (GPU driver id)");
    decode("DRM_IOCTL_MODE_MAP_DUMB", DRM_IOCTL_MODE_MAP_DUMB, "struct drm_mode_map_dumb * (GPU buffer -> mmap offset)");
    printf("\nSeccomp sees: syscall=ioctl, arg0=fd (int), arg1=request (the decoded word above), "
           "arg2=pointer (value only).\n");
    printf("It does NOT see: the struct behind arg2, nor which /dev node fd refers to. "
           "A meaningful ioctl policy is therefore per-driver and per-request-number, device-specific.\n");
    return 0;
}
