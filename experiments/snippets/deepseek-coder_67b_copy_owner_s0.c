#include <string.h>

struct res {
    char owner[16];
    long rid;
};

void copy_owner(struct res *s, const char *input) {
    strncpy(s->owner, input, sizeof(s->owner)-1);
    s->owner[sizeof(s->owner)-1] = '\0'; // Ensure null termination
}