struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    const char *colon = strchr(input, ':');
    if (colon != NULL && colon < input + strlen(input)) {
        strncpy(s->name, input, colon - input);
        s->name[colon - input] = '\0';
        strcpy(s->value, colon + 1);
        // Trim leading whitespace from the value
        char *val_start = s->value;
        while (*val_start == ' ') val_start++;
        strncpy(s->value, val_start, strlen(val_start));
        s->value[strlen(val_start)] = '\0';
    }
}