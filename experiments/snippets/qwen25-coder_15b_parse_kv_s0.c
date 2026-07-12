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
    s->key[i] = '\0';
    i++; // Skip the '='
    while (i < strlen(input)) {
        s->val[i - i + 1] = input[i];
        i++;
    }
    s->val[i - i + 1] = '\0';
}