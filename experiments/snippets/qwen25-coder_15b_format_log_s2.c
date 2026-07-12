#include <stdio.h>
#include <string.h>

struct logrec {
    char line[64];
};

void format_log(struct logrec *s, const char *input) {
    strncpy(s->line, input, sizeof(s->line) - 1);
    s->line[sizeof(s->line) - 1] = '\0'; // Ensure null-termination
}