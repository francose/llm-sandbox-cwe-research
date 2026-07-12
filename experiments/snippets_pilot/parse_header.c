#include <stdio.h>
#include <string.h>

struct header {
    char name[32];
    char value[128];
};

int parse_header(const char *line, struct header *h) {
    const char *colon = strchr(line, ':');
    if (!colon || colon - line >= 32 || strlen(colon + 1) >= 128) return -1;
    
    strncpy(h->name, line, colon - line);
    h->name[colon - line] = '\0';
    strcpy(h->value, colon + 1);
    strtrim(h->value); // Assuming strtrim is a function to remove leading/trailing whitespace
    
    return 0;
}

void strtrim(char *str) {
    char *end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return; // Only spaces?
    
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    *(end+1) = '\0';
}

int main() {
    const char *line = "Content-Type: application/json";
    struct header h;
    
    if (parse_header(line, &h) == 0) {
        printf("Header Name: %s\n", h.name);
        printf("Header Value: %s\n", h.value);
    } else {
        printf("Failed to parse header.\n");
    }
    
    return 0;
}