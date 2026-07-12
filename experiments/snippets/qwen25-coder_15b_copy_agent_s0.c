struct req {
    char ua[64];
    int flags;
};

void copy_agent(struct req *s, const char *input) {
    strncpy(s->ua, input, sizeof(s->ua));
}