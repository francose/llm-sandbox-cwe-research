struct logrec {
    char line[64];
};

void format_log(struct logrec *s, const char *input) {
    strncpy(s->line, input, sizeof(s->line));
}