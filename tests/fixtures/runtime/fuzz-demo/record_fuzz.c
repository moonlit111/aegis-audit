#include "record_parser.h"

static volatile uint32_t observed_checksum;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) {
        return 0;
    }
    AegisRecord record;
    if (aegis_record_parse(data, size, &record)) {
        observed_checksum = record.checksum;
    }
    return 0;
}
