#include <stdio.h>
#include <string.h>

struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    char *name = strtok((char*)input, ":");
    if (name != NULL && s != NULL) {
        strncpy(s->name, name, sizeof(s->name));
        
        // Remove leading whitespace
        while (*(strtok(NULL, ":")) == ' ') {}
            
        char *value = strtok(NULL, "\n");
        if (value != NULL) {
            strncpy(s->value, value, sizeof(s->value));
        } else {
            s->value[0] = '\0';
        }
    }
}