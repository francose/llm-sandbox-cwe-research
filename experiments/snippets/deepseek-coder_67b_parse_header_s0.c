#include <string.h>

struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    // Find the colon in the input string
    char* colon = strchr(input, ':');
    
    if (colon != NULL) {
        // Calculate the length of the name and value
        int name_length = colon - input;
        int value_length = strlen(colon + 1);  // Plus one to exclude the colon
        
        // Check for buffer overflows
        if (name_length > 31 || value_length > 127) {
            return;
        }
        
        // Copy the name and value into the struct
        strncpy(s->name, input, name_length);
        s-<｜begin▁of▁sentence｜>value, colon + 1, value_length);  // Plus one to exclude the colon
    }
}