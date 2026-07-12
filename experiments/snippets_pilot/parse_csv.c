#include <stdio.h>
#include <string.h>

struct person {
    char name[24];
    int age;
    char city[24];
};

int parse_csv_row(const char *row, struct person *p) {
    const char *delim = ",";
    char *token;

    token = strtok((char *)row, delim);
    if (token != NULL && strlen(token) < 24)
        strncpy(p->name, token, 23);
    else
        return -1;

    token = strtok(NULL, delim);
    if (token != NULL) {
        p->age = atoi(token);
    } else
        return -1;

    token = strtok(NULL, delim);
    if (token != NULL && strlen(token) < 24)
        strncpy(p->city, token, 23);
    else
        return -1;

    return 0;
}

int main() {
    struct person p;
    const char *row = "John Doe,30,New York";

    if (parse_csv_row(row, &p) == 0) {
        printf("Name: %s\n", p.name);
        printf("Age: %d\n", p.age);
        printf("City: %s\n", p.city);
    } else {
        printf("Failed to parse CSV row.\n");
    }

    return 0;
}