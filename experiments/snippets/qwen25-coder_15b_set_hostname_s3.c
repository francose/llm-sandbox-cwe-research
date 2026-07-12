#include <stdio.h>
#include <string.h>

struct node {
    char host[32];
    int port;
};

void set_hostname(struct node *s, const char *input) {
    if (strlen(input) > 31) { // Ensure the input string does not exceed 31 characters
        strcpy(s->host, "HostnameTooLong");
    } else {
        strcpy(s->host, input);
    }
}