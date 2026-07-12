#include <string.h>

struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    char* equalSign = strchr(input, '=');
    
    if (equalSign != NULL && equalSign > input) { // Ensure there's a '=' and it isn't at the start of the string
        size_t keyLen = equalSign - input;
        
        strncpy(s->key, input, keyLen);
        s->key[keyLen] = '\0'; // Null terminate the key

        strcpy(s->val, equalSign + 1); // Copy value after '='
    }
}