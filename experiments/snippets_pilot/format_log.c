#include <stdio.h>
#include <string.h>

struct log {
    char line[64];
};

void format_log(struct log *log_entry, const char *level, const char *msg) {
    snprintf(log_entry->line, sizeof(log_entry->line), "%s: %s", level, msg);
}

int main() {
    struct log my_log;
    format_log(&my_log, "INFO", "This is a test message.");
    printf("%s\n", my_log.line);
    return 0;
}