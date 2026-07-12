#include <string.h>
#include <stdlib.h>
#include <stdio.h>
struct packet { unsigned char type; unsigned short len; char payload[64]; };
int parse_packet(const unsigned char *buf, size_t n, struct packet *p){
    if (n < sizeof(struct packet)) return -1;
    p->type = buf[0];
    p->len = (buf[1] << 8) | buf[2];
    if (p->len > sizeof(p->payload)) return -2;
    if (n < sizeof(struct packet) + p->len) return -3;
    memcpy(p->payload, buf + sizeof(struct packet), p->len);
    p->payload[p->len] = '\0';   /* off-by-one when len==64 */
    return 0;
}
int main(void){
    size_t n = sizeof(struct packet) + 64;
    unsigned char *buf = calloc(1, n);
    buf[1]=0; buf[2]=64;                 /* len = 64 */
    struct packet *p = malloc(sizeof *p);
    printf("parse_packet rc=%d\n", parse_packet(buf, n, p));
    return 0;
}
