struct entry {
    char key[32];
    long hash;
};

void store_key(struct entry *s, const char *input) {
    strncpy(s->key, input, sizeof(s->key));
}