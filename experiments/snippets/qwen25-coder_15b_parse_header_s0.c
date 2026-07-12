struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    // Split the input string by colon to separate name and value
    char *name_start = strstr(input, ": ");
    if (name_start == NULL) {
        // Handle error: no colon found in the input
        return;
    }

    // Copy the name part up to the first colon
    strncpy(s->name, input, name_start - input);
    s->name[name_start - input] = '\0';

    // Skip the colon and any leading whitespace
    char *value_start = name_start + 2;
    while (*value_start == ' ') {
        value_start++;
    }

    // Copy the value part up to the end of the line
    strncpy(s->value, value_start, sizeof(s->value) - 1);
    s->value[sizeof(s->value) - 1] = '\0';
}