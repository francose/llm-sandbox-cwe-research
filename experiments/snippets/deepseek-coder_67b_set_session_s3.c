#include <string.h>

struct session {
    char user[16];
    int token;
};

void set_session(struct session *s, const char *input) {
    strncpy(s->user, input, sizeof(s->user)-1);
    s->user[sizeof(s->user)-1] = '\0';  // Ensure null termination
}