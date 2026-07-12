#include <string.h>

struct doc {
    char title[48];
    long id; 
};

void set_title(struct doc *s, const char *input) {
    strncpy(s->title, input, sizeof(s->title)-1);
}