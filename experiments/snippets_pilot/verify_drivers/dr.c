#include <string.h>
#include <stdlib.h>
#include <stdio.h>
struct record { char name[20]; unsigned int id; };
void deserialize_record(const unsigned char *bytes, struct record *r){
    memcpy(r->name, bytes, 20);
    r->id = *(unsigned int *)(bytes + 20);   /* reads bytes[20..23], no bound */
}
int main(void){
    unsigned char *bytes = malloc(20);       /* only 20 bytes exist */
    memset(bytes, 'A', 20);
    struct record *r = malloc(sizeof *r);
    deserialize_record(bytes, r);
    printf("id=%u\n", r->id);
    return 0;
}
