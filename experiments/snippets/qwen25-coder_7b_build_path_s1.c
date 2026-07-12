struct fullpath {
    char buf[80];
};

void build_path(struct fullpath *s, const char *input) {
    snprintf(s->buf, sizeof(s->buf), "%s", input);
}