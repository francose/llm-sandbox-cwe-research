#include <stdio.h>
#include <string.h>

struct req {
    char ua[64];
    int flags;
};

void copy_agent(struct req *s, const char *input) {
    strcpy(s->ua, input);
}