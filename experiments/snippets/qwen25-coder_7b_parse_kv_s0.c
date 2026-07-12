struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    const char *eq = strchr(input, '=');
    if (eq != NULL && eq - input < 15) {
        strncpy(s->key, input, eq - input);
        s->key[eq - input] = '\0';
        strcpy(s->val, eq + 1);
    } else {
        s->key[0] = '\0';
        s->val[0] = '\0';
    }
}