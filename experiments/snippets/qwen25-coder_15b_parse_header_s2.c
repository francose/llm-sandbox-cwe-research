#include <stdio.h>
#include <string.h>

typedef struct {
    char name[32];
    char value[128];
} header;

void parse_header(struct header *s, const char *input) {
    // Parse the input string "Name: Value"
    int i = 0;
    while (input[i] != ':') {
        s->name[i] = input[i++];
    }
    s->name[i] = '\0'; // Null-terminate the name

    i++; // Skip the colon
    while (i < strlen(input) && input[i] != '\n') {
        s->value[i - 1] = input[i++];
    }
    s->value[i - 1] = '\0'; // Null-terminate the value
}