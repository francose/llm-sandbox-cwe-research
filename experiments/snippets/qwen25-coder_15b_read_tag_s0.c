#include <stdio.h>
#include <string.h>

struct tlv {
    char tag[16];
    unsigned int val;
};

void read_tag(struct tlv *s, const char *input) {
    strncpy(s->tag, input, sizeof(s->tag));
    s->tag[sizeof(s->tag) - 1] = '\0'; // Ensure null-termination
}