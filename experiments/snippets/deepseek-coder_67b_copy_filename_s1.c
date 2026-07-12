#include <string.h>

struct file_entry {
    char path[64];
    long size;
};

void copy_filename(struct file_entry *s, const char *input) {
    strncpy(s->path, input, sizeof(s->path));
}