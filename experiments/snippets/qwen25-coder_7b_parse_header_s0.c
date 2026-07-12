struct header {
    char name[32];
    char value[128];
};

void parse_header(struct header *s, const char *input) {
    const char *colon = strchr(input, ':');
    if (colon != NULL) {
        size_t name_len = colon - input;
        if (name_len < sizeof(s->name)) {
            strncpy(s->name, input, name_len);
            s->name[name_len] = '\0';
        }
        const char *value_start = colon + 1;
        while (*value_start == ' ') value_start++;
        size_t value_len = strlen(value_start);
        if (value_len < sizeof(s->value)) {
            strncpy(s->value, value_start, value_len);
            s->value[value_len] = '\0';
        }
    } else {
        s->name[0] = '\0';
        s->value[0] = '\0';
    }
}