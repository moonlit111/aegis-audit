#include <stdio.h>
#include <string.h>

int main(void) {
    char input[512], output[16];
    if (!fgets(input, sizeof(input), stdin)) return 0;
    if (strlen(input) >= sizeof(output)) return 0;
    memcpy(output, input, strlen(input) + 1);
    puts(output);
    return 0;
}
