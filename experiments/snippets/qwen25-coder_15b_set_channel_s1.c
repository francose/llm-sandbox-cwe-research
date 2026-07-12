struct sub {
    char chan[32];
    int count;
};

void set_channel(struct sub *s, const char *input) {
    strncpy(s->chan, input, sizeof(s->chan) - 1); // Ensure null terminator is added
    s->chan[sizeof(s->chan) - 1] = '\0'; // Explicitly add null terminator
}