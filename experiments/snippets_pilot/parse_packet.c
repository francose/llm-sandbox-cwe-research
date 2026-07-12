#include <stdio.h>
#include <stdint.h>

struct packet {
    unsigned char type;
    unsigned short len;
    char payload[64];
};

int parse_packet(const unsigned char *buf, size_t n, struct packet *p) {
    if (n < sizeof(struct packet)) {
        return -1; // Not enough data for a complete packet
    }

    p->type = buf[0];
    p->len = (buf[1] << 8) | buf[2];

    if (p->len > sizeof(p->payload)) {
        return -2; // Payload too large
    }

    if (n < sizeof(struct packet) + p->len) {
        return -3; // Not enough data for the payload
    }

    memcpy(p->payload, buf + sizeof(struct packet), p->len);
    p->payload[p->len] = '\0'; // Null-terminate the payload

    return 0; // Success
}

int main() {
    const unsigned char buf[] = {0x01, 0x00, 0x20, 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '\0'};
    size_t n = sizeof(buf);
    struct packet p;

    if (parse_packet(buf, n, &p) == 0) {
        printf("Type: %d\n", p.type);
        printf("Length: %d\n", p.len);
        printf("Payload: %s\n", p.payload);
    } else {
        printf("Failed to parse packet.\n");
    }

    return 0;
}