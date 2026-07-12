#include <string.h>

struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    char *equal = strchr(input, '=');
    if (equal != NULL) {
        size_t keyLen = equal - input;
        if (keyLen < sizeof(s->key)) {
            strncpy(s->key, input, keyLen);
            s->key[keyLen] = '\0';  // Null terminate the string
        } else {
            // The key is too long. Handle this error case if necessary.
        }
        
        size_t valLen = strlen(equal + 1);
        if (valLen < sizeof(s->val)) {
            strncpy(s->val, equal + 1, valLen);
            s->val[valLen] = '\0';  // Null terminate the string
        } else {
            // The value is too long. Handle this error case if necessary.
        }
    } else {
        // No '=' found in input. Handle this error case if necessary.
    }
}