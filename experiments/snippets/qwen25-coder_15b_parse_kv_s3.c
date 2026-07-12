struct kv {
    char key[16];
    char val[48];
};

void parse_kv(struct kv *s, const char *input) {
    const char *key_start = input;
    while (*input != '=' && *input != '\0') input++;
    if (*input == '=') { // Found the '='
        *input++ = '\0'; // Null terminate key and val
        strncpy(s->key, key_start, sizeof(s->key) - 1);
        s->key[sizeof(s->key) - 1] = '\0'; // Ensure null termination

        while (*input != '\0') input++;
        strncpy(s->val, input, sizeof(s->val) - 1);
        s->val[sizeof(s->val) - 1] = '\0'; // Ensure null termination
    }
}