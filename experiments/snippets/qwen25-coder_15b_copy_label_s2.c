#include <stdio.h>

struct item {
    char label[24];
    int qty;
};

void copy_label(struct item *s, const char *input) {
    if (strlen(input) < sizeof(s->label)) {
        strcpy(s->label, input);
    } else {
        printf("Error: Input string is too long for the structure.\n");
    }
}