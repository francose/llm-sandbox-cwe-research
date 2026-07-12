#include <stdio.h>
#include <string.h>

struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    if (sscanf(input, "%[^:]: %[^\n]", s->name, s->value) == 2) {
        printf("Parsed Name: %s\n", s->name);
        printf("Parsed Value: %s\n", s->value);
    } else {
        printf("Invalid header format.\n");
    }
}