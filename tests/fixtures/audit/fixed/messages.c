#include <stdio.h>
#include <string.h>

void print_message(const char *message) {
    char buffer[16];
    if (strlen(message) >= sizeof(buffer)) return;
    memcpy(buffer, message, strlen(message) + 1);
    puts(buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) print_message(argv[1]);
    return 0;
}
