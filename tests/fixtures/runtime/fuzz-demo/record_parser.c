#include "record_parser.h"
#include <string.h>

#ifndef AEGIS_RECORD_FIXED
#define AEGIS_RECORD_FIXED 0
#endif

int aegis_record_parse(const uint8_t *data, size_t size, AegisRecord *record) {
    const size_t header_size = 8;
    if (size < header_size || memcmp(data, "AEG1|", 5) != 0 || data[7] != '|') {
        return 0;
    }
    if (data[5] < '0' || data[5] > '9' || data[6] < '0' || data[6] > '9') {
        return 0;
    }

    size_t declared = (size_t)(data[5] - '0') * 10 + (size_t)(data[6] - '0');
    if (declared >= sizeof(record->text)) {
        return 0;
    }
#if AEGIS_RECORD_FIXED
    if (declared > size - header_size) {
        return 0;
    }
#endif

    // The demonstration defect is the missing source-length check above.
    // Destination capacity is checked in both versions; only the read differs.
    record->checksum = 2166136261u;
    for (size_t index = 0; index < declared; ++index) {
        uint8_t value = data[header_size + index];
        record->text[index] = (char)value;
        record->checksum = (record->checksum ^ value) * 16777619u;
    }
    record->text[declared] = '\0';
    record->length = declared;
    return 1;
}
