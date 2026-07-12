#include <string.h>

struct fullpath {
    char buf[80];
};

void build_path(struct fullpath *s, const char *input) {
    strncpy(s->buf, input, sizeof(s->buf)-1);
}