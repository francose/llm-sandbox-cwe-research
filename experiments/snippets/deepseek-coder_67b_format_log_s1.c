struct logrec {
    char line[64];
};

void format_log(struct logrec *s, const char *input) {
    strncpy(s->line, input, sizeof(s->line));
    s->line[sizeof(s->line)-1] = '\0'; // Ensure null termination in case the string is longer than 64 characters.
}