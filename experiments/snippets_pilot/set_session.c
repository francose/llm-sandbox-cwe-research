#include <stdio.h>
#include <string.h>

struct session {
    char user[16];
    int token;
};

void copy_username(struct session *sess, const char *arg) {
    strncpy(sess->user, arg, sizeof(sess->user) - 1);
    sess->user[sizeof(sess->user) - 1] = '\0';
}

int main() {
    struct session my_session;
    const char *username = "example_user";
    
    copy_username(&my_session, username);
    
    printf("Username: %s\n", my_session.user);
    
    return 0;
}