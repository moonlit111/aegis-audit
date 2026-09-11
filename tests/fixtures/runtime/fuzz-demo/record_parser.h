#ifndef AEGIS_RECORD_PARSER_H
#define AEGIS_RECORD_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t length;
    uint32_t checksum;
    char text[64];
} AegisRecord;

int aegis_record_parse(const uint8_t *data, size_t size, AegisRecord *record);

#endif
