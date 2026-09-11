#ifndef AEGIS_NATIVE_TOOL_H
#define AEGIS_NATIVE_TOOL_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#ifndef TOOL_FIXED
#define TOOL_FIXED 0
#endif
#ifndef TOOL_PROTECTED
#define TOOL_PROTECTED 0
#endif

void *memset(void *destination, int value, size_t count) {
    volatile unsigned char *out = (volatile unsigned char *)destination;
    while (count--) *out++ = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, size_t count) {
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    while (count--) *out++ = *in++;
    return destination;
}

static void message(const char *text) {
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, (DWORD)lstrlenA(text), &written, NULL);
}

static BOOL read_bytes(const WCHAR *path, unsigned char *buffer, DWORD capacity, DWORD *length) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER size;
    BOOL ok;
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    ok = GetFileSizeEx(file, &size) && size.QuadPart >= 0 && size.QuadPart <= capacity;
    if (ok) ok = ReadFile(file, buffer, (DWORD)size.QuadPart, length, NULL) &&
                 *length == (DWORD)size.QuadPart;
    CloseHandle(file);
    return ok;
}

static BOOL utf8(const WCHAR *value, char *buffer, int capacity) {
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
                               buffer, capacity, NULL, NULL) != 0;
}

static BOOL wide(const char *value, WCHAR *buffer, int capacity) {
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1,
                               buffer, capacity) != 0;
}

__declspec(noinline) static void reveal(const unsigned char *input, unsigned count,
                                       unsigned char key, char *output) {
    volatile unsigned char mask = key;
    unsigned index;
    for (index = 0; index < count; ++index) output[index] = (char)(input[index] ^ mask);
    output[count] = 0;
}

static int tool_main(int argc, WCHAR **argv);

void entry(void) {
    int argc = 0;
    int result;
    WCHAR **argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) ExitProcess(3);
    result = tool_main(argc, argv);
    LocalFree(argv);
    ExitProcess((UINT)result);
}

#endif
