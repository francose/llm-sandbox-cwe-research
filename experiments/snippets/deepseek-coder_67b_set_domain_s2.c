#include <string.h> // For strncpy()

struct dns {
    char domain[64]; 
    unsigned short qtype; 
};

void set_domain(struct dns *s, const char *input) {
    if (strlen(input) < 64) {
        strcpy(s->domain, input); // Copy the string into domain field
    } else {
        strncpy(s->domain, input, 63); // Ensure that there is space for null terminator
        s->domain[63] = '\0'; // Null terminate the string
    }
}