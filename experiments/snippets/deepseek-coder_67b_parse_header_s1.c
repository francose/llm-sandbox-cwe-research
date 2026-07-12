#include <string.h>

struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    char *colon = strchr(input, ':');
    
    if (colon != NULL && colon - input < 31) {
        int nameLen = (int)(colon - input);
        strncpy(s->name, input, nameLen);
        s->name[nameLen] = '\0';
        
        // Skip the colon and spaces
        while (*(colon+1) == ' ') {
            colon++;
        }
        
        strncpy(s->value, colon + 1, 127);
        s->value[strlen(s->value)] = '\0'; // Null terminate the value string
    } else {
        s->name[0] = '\0';
        s->value[0] = '\0';
    }
}