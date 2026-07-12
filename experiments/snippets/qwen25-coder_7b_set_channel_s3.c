struct sub {
    char chan[32];
    int count;
};

void set_channel(struct sub *s, const char *input) {
    snprintf(s->chan, sizeof(s->chan), "%s", input);
}