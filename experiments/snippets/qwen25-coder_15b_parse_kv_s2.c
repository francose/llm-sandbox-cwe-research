struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    int i = 0;
    while (input[i] != '=') {
        s->key[i] = input[i];
        i++;
    }
    s->key[i++] = '\0';
    while (i < strlen(input)) {
        s->val[i - strlen(s->key)] = input[i];
        i++;
    }
    s->val[i - strlen(s->key)] = '\0';
}