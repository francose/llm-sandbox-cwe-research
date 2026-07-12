struct user {
    char name[16];
    int uid;
};

void set_user_name(struct user *s, const char *input) {
    strncpy(s->name, input, sizeof(s->name));
}