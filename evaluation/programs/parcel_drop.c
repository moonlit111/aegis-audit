#include "native_tool.h"

// Keep only the final path component and drop characters the flat inbox cannot hold.
static void entry_name(const WCHAR *name, WCHAR *output, int capacity) {
    const WCHAR *leaf = name;
    int index;
    int length = 0;
    WCHAR kept[256];
    for (index = 0; name[index]; ++index) {
        if (name[index] == L'\\' || name[index] == L'/') leaf = name + index + 1;
    }
    while (leaf[length] && length < capacity - 1) {
        WCHAR c = leaf[length];
        if (c < 32 || c == L'<' || c == L'>' || c == L':' || c == L'"' ||
            c == L'|' || c == L'?' || c == L'*') c = L'_';
        output[length++] = c;
    }
    while (length > 0 && (output[length - 1] == L'.' || output[length - 1] == L' '))
        output[--length] = 0;
    output[length] = 0;
    if (!length || !lstrcmpW(output, L".") || !lstrcmpW(output, L"..")) {
        lstrcpynW(output, L"import.dat", capacity);
        return;
    }
    if (!lstrcmpiW(output, L"CON") || !lstrcmpiW(output, L"PRN") ||
        !lstrcmpiW(output, L"AUX") || !lstrcmpiW(output, L"NUL")) {
        lstrcpynW(kept, output, 250);
        lstrcpynW(output, L"_", capacity);
        lstrcatW(output, kept);
    }
}

static int tool_main(int argc, WCHAR **argv) {
    WCHAR destination[1024];
    WCHAR entry[256];
    DWORD attributes;
    if (argc != 4) {
        message("ParcelDrop 1.0\nUsage: ParcelDrop.exe INBOX ENTRY_NAME PAYLOAD_FILE\n");
        return 2;
    }
    if (TOOL_FIXED) entry_name(argv[2], entry, 256);
    else lstrcpynW(entry, argv[2], 256);
    if (lstrlenW(argv[1]) + lstrlenW(entry) + 2 >= 1024) return 2;
    if (!CreateDirectoryW(argv[1], NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return 3;
    attributes = GetFileAttributesW(argv[1]);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return 3;
    lstrcpyW(destination, argv[1]);
    lstrcatW(destination, L"\\");
    lstrcatW(destination, entry);
    if (!CopyFileW(argv[3], destination, TRUE)) {
        message("Import failed; existing files are not overwritten.\n");
        return 3;
    }
    message("Entry imported.\n");
    return 0;
}
