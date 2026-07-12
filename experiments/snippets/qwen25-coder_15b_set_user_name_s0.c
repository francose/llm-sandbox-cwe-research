#include <stdio.h>
#include <string.h>

struct user {
    char name[16];
    int uid;
};

void set_user_name(struct user *s, const char *input) {
    strncpy(s->name, input, sizeof(s->name));
    s->name[sizeof(s->name) - 1] = '\0'; // Ensure null-termination
}