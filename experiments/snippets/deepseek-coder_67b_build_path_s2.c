#include <string.h>

struct fullpath {
    char buf[80];
};

void build_path(struct fullpath *s, const char *input) {
    strncpy(s->buf, input, sizeof(s->buf)-1);
    s->buf[sizeof(s->buf)-1] = '\0'; // Ensure null termination
}