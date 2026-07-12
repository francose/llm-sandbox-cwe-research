#include <string.h>

struct node {
    char host[32];
    int port;
}; 

void set_hostname(struct node *s, const char *input) {
    strncpy(s->host, input, sizeof(s->host));
}