struct dns {
    char domain[64];
    unsigned short qtype;
};

void set_domain(struct dns *s, const char *input) {
    strncpy(s->domain, input, sizeof(s->domain) - 1);
    s->domain[sizeof(s->domain) - 1] = '\0';
}