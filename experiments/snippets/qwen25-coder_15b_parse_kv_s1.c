#include <stdio.h>
#include <string.h>

struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    if (input == NULL || strlen(input) >= sizeof(s->key)) {
        return; // Invalid input or too long
    }
    
    int i = 0;
    while (i < strlen(input) && input[i] != '=') {
        s->key[i] = input[i];
        i++;
    }
    if (i == strlen(input)) {
        return; // No '=' found in the input
    }
    s->key[i++] = '\0';
    
    while (i < strlen(input)) {
        s->val[i - i + 1] = input[i];
        i++;
    }
    s->val[i - i] = '\0'; // Null-terminate the val string
}