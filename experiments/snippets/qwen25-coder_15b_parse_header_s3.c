struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    if (!input) return;

    // Initialize both strings to empty
    memset(s->name, '\0', sizeof(s->name));
    memset(s->value, '\0', sizeof(s->value));

    // Split the input string by ':'
    char *token = strtok(input, ":");
    if (token == NULL) {
        // No colon found, invalid header format
        return;
    }

    // Copy the name part to s->name
    strncpy(s->name, token, sizeof(s->name) - 1);
    s->name[sizeof(s->name) - 1] = '\0'; // Ensure null-terminated

    // Skip the colon
    token = strtok(NULL, ":");
    if (token == NULL) {
        // No value found after name part
        return;
    }

    // Copy the value part to s->value
    strncpy(s->value, token, sizeof(s->value) - 1);
    s->value[sizeof(s->value) - 1] = '\0'; // Ensure null-terminated
}