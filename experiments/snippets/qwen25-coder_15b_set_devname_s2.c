struct dev {
    char name[20];
    int major;
};

void set_devname(struct dev *s, const char *input) {
    strncpy(s->name, input, sizeof(s->name) - 1); // Ensure null-termination
    s->name[sizeof(s->name) - 1] = '\0'; // Explicitly add null terminator
}