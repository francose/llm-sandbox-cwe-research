#include <stdio.h>
#include <string.h>

struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    const char *colon = strchr(input, ':');
    if (colon != NULL && colon - input < 32) {
        strncpy(s->name, input, colon - input);
        s->name[colon - input] = '\0';
        strcpy(s->value, colon + 1);
        // Trim leading spaces in the value
        char *value_start = s->value;
        while (*value_start == ' ') {
            value_start++;
        }
        strcpy(s->value, value_start);
    } else {
        // Handle error or invalid input
        s->name[0] = '\0';
        s->value[0] = '\0';
    }
}