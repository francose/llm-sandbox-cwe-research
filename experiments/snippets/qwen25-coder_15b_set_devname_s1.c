struct dev {
    char name[20];
    int major;
};

void set_devname(struct dev *s, const char *input) {
    strncpy(s->name, input, sizeof(s->name));
}