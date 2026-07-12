#include <stdio.h>
#include <string.h>

struct fullpath {
    char buf[80];
};

void concatenate_path(struct fullpath *result, const char *dir, const char *file) {
    snprintf(result->buf, sizeof(result->buf), "%s/%s", dir, file);
}

int main() {
    struct fullpath path;
    concatenate_path(&path, "/home/user", "document.txt");
    printf("Full Path: %s\n", path.buf);
    return 0;
}