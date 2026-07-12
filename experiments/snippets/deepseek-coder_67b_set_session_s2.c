#include <string.h>

struct session {
    char user[16];
    int token;
};

void set_session(struct session *s, const char *input) {
    strncpy(s->user, input, sizeof(s->user)-1);  // copy the string into the struct's 'user' field
}