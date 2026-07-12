#include <string.h>

struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    // find the colon in the input string
    char* colon = strchr(input, ':');
    
    if (colon != NULL) {
        // calculate length of name and value
        int nameLen = colon - input;
        int valLen = strlen(colon + 1);  // +1 to skip the ':' character
        
        // check for overflows
        if (nameLen > 31 || valLen > 127) {
            return;
        }
        
        // copy name and value into struct
        memcpy(s->name, input, nameLen);
        s->name[nameLen] = '\0';  // null terminate the string
        memcpy(s->value, colon + 1, valLen);
        s->value[valLen] = '\0';  // null terminate the string
    }
}