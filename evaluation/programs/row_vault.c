#include "native_tool.h"

static unsigned char input[512];

static int tool_main(int argc, WCHAR **argv) {
    DWORD length = 0;
    DWORD written;
    unsigned count;
    unsigned index;
    SYSTEM_INFO info;
    unsigned char *pages;
    volatile unsigned char *label;
    if (argc != 2) {
        message("RowVault 1.0\nUsage: RowVault.exe RECORD.rv\n");
        return 2;
    }
    if (!read_bytes(argv[1], input, sizeof(input), &length) || length < 4 ||
        input[0] != 'R' || input[1] != 'V' || input[2] != '1') return 2;
    count = input[3];
    if (length != count + 4) return 2;
    if (TOOL_FIXED && count > 32) {
        message("Record label truncated to the supported width.\n");
        count = 32;
    }
    GetSystemInfo(&info);
    pages = (unsigned char *)VirtualAlloc(NULL, info.dwPageSize * 2,
                                          MEM_RESERVE, PAGE_NOACCESS);
    if (!pages) return 3;
    if (!VirtualAlloc(pages, info.dwPageSize, MEM_COMMIT, PAGE_READWRITE)) {
        VirtualFree(pages, 0, MEM_RELEASE);
        return 3;
    }
    // Keep the record workspace adjacent to an inaccessible guard page.
    label = pages + info.dwPageSize - 32;
    for (index = 0; index < count; ++index) label[index] = input[index + 4];
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), (const void *)label, count, &written, NULL);
    message("\n");
    VirtualFree(pages, 0, MEM_RELEASE);
    return 0;
}
