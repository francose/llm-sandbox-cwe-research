#include <stdio.h>
#include <string.h>

struct dns_query {
    char domain[64];
    unsigned short qtype;
};

void fill_dns_query(struct dns_query *query, const char *domain) {
    strncpy(query->domain, domain, sizeof(query->domain) - 1);
    query->domain[sizeof(query->domain) - 1] = '\0';
    query->qtype = 1; // Assuming A record for simplicity
}

int main() {
    struct dns_query query;
    const char *domain = "example.com";

    fill_dns_query(&query, domain);

    printf("Domain: %s\n", query.domain);
    printf("QType: %u\n", query.qtype);

    return 0;
}