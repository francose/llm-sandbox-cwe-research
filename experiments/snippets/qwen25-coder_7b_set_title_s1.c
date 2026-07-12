struct doc {
    char title[48];
    long id;
};

void set_title(struct doc *s, const char *input) {
    strncpy(s->title, input, sizeof(s->title) - 1);
    s->title[sizeof(s->title) - 1] = '\0';
}