struct logrec {
    char line[64];
};

void format_log(struct logrec *s, const char *input) {
    if (strlen(input) < 63) {
        strncpy(s->line, input, sizeof(s->line));
        s->line[sizeof(s->line) - 1] = '\0'; // Ensure null-termination
    } else {
        // Handle the case where the input is longer than the line field
        // For example, you could truncate the input or log an error message
        fprintf(stderr, "Input exceeds logrec line length.\n");
    }
}