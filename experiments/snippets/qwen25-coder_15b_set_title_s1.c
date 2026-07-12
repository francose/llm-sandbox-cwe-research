struct doc {
    char title[48];
    long id;
};

void set_title(struct doc *s, const char *input) {
    strcpy(s->title, input);
}