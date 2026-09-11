#include "record_parser.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("RecordView: local record-file inspector (self-authored demo)");
        puts("Usage: RecordView.exe INPUT_FILE");
        puts("Record format: AEG1|NN|TEXT, where NN is the decimal byte length.");
        return argc == 1 ? 0 : 2;
    }
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) {
        fputs("Cannot open the input file.\n", stderr);
        return 2;
    }
    if (fseek(input, 0, SEEK_END) != 0) {
        fclose(input);
        return 2;
    }
    long length = ftell(input);
    if (length < 0 || length > 4096 || fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        fputs("Input must contain at most 4096 bytes.\n", stderr);
        return 2;
    }
    uint8_t *data = (uint8_t *)malloc(length > 0 ? (size_t)length : 1);
    if (data == NULL) {
        fclose(input);
        return 2;
    }
    size_t size = fread(data, 1, (size_t)length, input);
    int failed = ferror(input);
    fclose(input);
    if (failed || size != (size_t)length) {
        free(data);
        return 2;
    }
    AegisRecord record;
    int accepted = aegis_record_parse(data, size, &record);
    free(data);
    if (!accepted) {
        puts("Rejected: invalid or incomplete record.");
        return 3;
    }
    printf("Accepted: length=%zu checksum=%08x text=%s\n", record.length, (unsigned)record.checksum, record.text);
    return 0;
}
