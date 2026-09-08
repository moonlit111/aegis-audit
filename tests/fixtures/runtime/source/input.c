#include <stdio.h>
#include <string.h>

int main(void) {
    char input[512], output[16];
    if (!fgets(input, sizeof(input), stdin)) return 0;
    strcpy(output, input);
    puts(output);
    return 0;
}
