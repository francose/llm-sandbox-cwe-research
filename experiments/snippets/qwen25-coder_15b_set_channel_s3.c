struct sub {
    char chan[32];
    int count;
};

void set_channel(struct sub *s, const char *input) {
    if (strlen(input) < sizeof(s->chan)) {
        strcpy(s->chan, input);
        s->count = 1; // Assuming the count starts at 1
    } else {
        // Handle error: input string is too long
        // For example, you could print an error message or return a failure code
    }
}