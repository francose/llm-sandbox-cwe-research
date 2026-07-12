#include <stdio.h>
#include <string.h>

struct record {
    char name[20];
    unsigned int id;
};

void deserialize_record(const unsigned char *bytes, struct record *r) {
    memcpy(r->name, bytes, 20);
    r->id = *(unsigned int *)(bytes + 20);
}

int main() {
    const unsigned char data[] = "John Doe\x00\x00\x00\x12";
    struct record rec;
    deserialize_record(data, &rec);
    printf("Name: %s\nID: %u\n", rec.name, rec.id);
    return 0;
}