#include <string.h>

struct sub {
    char chan[32];
    int count; 
};

void set_channel(struct sub *s, const char *input) {
    strncpy(s->chan, input, sizeof(s->chan));
}