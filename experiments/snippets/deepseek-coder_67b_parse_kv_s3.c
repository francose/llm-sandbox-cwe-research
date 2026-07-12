#include <string.h>

struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    // Find the equals sign in input string
    char* equals = strchr(input, '=');
    
    if (equals != NULL) {
        size_t keyLen = equals - input;  // Length of key part
        size_t valLen = strlen(equals + 1);  // Length of value part
        
        // Ensure that the struct can hold the parsed data without overflowing
        if (keyLen < 16 && valLen < 48) {
            // Copy the parts into their respective fields in s
            memcpy(s->key, input, keyLen);  
            s->key[keyLen] = '\0';  // Null terminate key for safety
            
            memcpy(s->val, equals + 1, valLen);
            s->val[valLen] = '\0';  // Null terminate value for safety
        }
    }
}