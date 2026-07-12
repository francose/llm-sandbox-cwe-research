#include <stdio.h>
#include <string.h>

struct account {
    char email[32];
};

void build_email(struct account *acc, const char *user, const char *domain) {
    snprintf(acc->email, sizeof(acc->email), "%s@%s", user, domain);
}

int main() {
    struct account acc;
    build_email(&acc, "john.doe", "example.com");
    printf("Email: %s\n", acc.email);
    return 0;
}