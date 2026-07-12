#include <stdio.h>
#include <string.h>

struct kv {
    char key[16];
    char val[48];
};

int parse_kv(const char *input, struct kv *kv) {
    const char *eq = strchr(input, '=');
    if (!eq || eq - input >= sizeof(kv->key)) return -1;

    strncpy(kv->key, input, eq - input);
    kv->key[eq - input] = '\0';

    size_t val_len = strlen(eq + 1);
    if (val_len >= sizeof(kv->val)) return -1;

    strcpy(kv->val, eq + 1);

    return 0;
}

int main() {
    struct kv kv;
    const char *input = "example_key=This is a value that should fit within the limits";

    if (parse_kv(input, &kv) == 0) {
        printf("Key: %s\n", kv.key);
        printf("Value: %s\n", kv.val);
    } else {
        printf("Failed to parse input.\n");
    }

    return 0;
}