#include <stdio.h>
#include <string.h>

struct file_entry {
    char path[64];
    long size;
};

void copy_filename(const char *input, struct file_entry *entry) {
    strncpy(entry->path, input, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';
    entry->size = 0; // Assuming size is not provided in the input
}

int main() {
    const char *filename = "example.txt";
    struct file_entry entry;
    copy_filename(filename, &entry);
    printf("Path: %s\n", entry.path);
    return 0;
}