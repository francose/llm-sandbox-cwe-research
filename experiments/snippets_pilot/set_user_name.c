#include <stdio.h>
#include <string.h>

struct user {
    char name[16];
    int uid;
};

void set_user_name(struct user *u, const char *input) {
    strncpy(u->name, input, sizeof(u->name) - 1);
    u->name[sizeof(u->name) - 1] = '\0';
}

int main() {
    struct user u;
    set_user_name(&u, "JohnDoe");
    printf("User name: %s\n", u.name);
    return 0;
}