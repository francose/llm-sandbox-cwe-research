#include <string.h>

struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    char *equalSign = strchr(input, '=');
    
    if (equalSign != NULL) {
        size_t keyLength = equalSign - input;
        
        // Ensure that the key fits into the struct
        if (keyLength >= sizeof(s->key)) {
            keyLength = sizeof(s->key) - 1;
        }
        
        strncpy(s->key, input, keyLength);
        s->key[keyLength] = '\0'; // Null terminate the string
        
        // Copy the value into the struct
        strcpy(s->val, equalSign + 1);
    } else {
        // If there is no '=' sign in the input, copy the whole input to key and clear val
        strncpy(s->key, input, sizeof(s->key) - 1);
        s->key[sizeof(s->key) - 1] = '\0'; // Null terminate the string
        
        memset(s->val, 0, sizeof(s->val)); // Clear val
    }
}