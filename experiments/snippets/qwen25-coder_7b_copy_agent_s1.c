struct req {
    char ua[64];
    int flags;
};

void copy_agent(struct req *s, const char *input) {
    snprintf(s->ua, sizeof(s->ua), "%s", input);
}