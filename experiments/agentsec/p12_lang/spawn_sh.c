// P12 target (C): after the legitimate launch, attempt to spawn a shell (the injected/autonomous act).
#include <unistd.h>
int main(void) {
    char *a[] = {"sh", "-c", "echo LANG_C_PWNED", 0};
    execve("/bin/sh", a, 0);   // second execve -> the gate must DENY this regardless of source language
    return 7;
}
