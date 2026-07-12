#include <string.h>

struct item {
    char label[24];
    int qty;
};

void copy_label(struct item *s, const char *input) {
    strncpy(s->label, input, sizeof(s->label)-1);
    s->label[sizeof(s->label)-1] = '\0'; // Ensure null termination
}