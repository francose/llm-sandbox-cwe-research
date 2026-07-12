#include <string.h>

struct entry {
    char key[32];
    long hash;
};

void store_key(struct entry *s, const char *input) {
    strncpy(s->key, input, sizeof(s->key)-1);  /* copy string into struct */
    s->key[sizeof(s->key)-1] = '\0';           /* ensure null termination */
}