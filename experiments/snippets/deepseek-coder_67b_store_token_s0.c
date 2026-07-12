#include <string.h>

struct auth {
    char token[32];
    long expiry;
};

void store_token(struct auth *s, const char *input) {
    strncpy(s->token, input, sizeof(s->token)-1);
}