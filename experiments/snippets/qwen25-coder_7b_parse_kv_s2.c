struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    const char *eq = strchr(input, '=');
    if (eq != NULL) {
        size_t key_len = eq - input;
        if (key_len < sizeof(s->key)) {
            strncpy(s->key, input, key_len);
            s->key[key_len] = '\0';
        }
        size_t val_len = strlen(eq + 1);
        if (val_len < sizeof(s->val)) {
            strcpy(s->val, eq + 1);
        }
    } else {
        s->key[0] = '\0';
        s->val[0] = '\0';
    }
}