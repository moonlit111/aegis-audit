#include "native_tool.h"

static int tool_main(int argc, WCHAR **argv) {
    char prefix[64], output_name[32];
    WCHAR output[32], command[1024], executable[MAX_PATH];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD result;
    unsigned state = 0x31;
    volatile DWORD noise = GetCurrentProcessId();
    if (argc != 2) {
        message("TextRelay 1.0\nUsage: TextRelay.exe DOCUMENT\n");
        return 2;
    }
#if TOOL_PROTECTED
    {
        static const unsigned char a[] = {14, 0, 9, 67, 8, 21, 8, 77, 66, 9, 77, 66, 14, 77, 25, 20, 29, 8, 77};
        static const unsigned char b[] = {31, 8, 1, 12, 20, 67, 25, 21, 25};
        reveal(a, sizeof(a), 0x6d, prefix);
        reveal(b, sizeof(b), 0x6d, output_name);
    }
#else
    lstrcpyA(prefix, "cmd.exe /d /c type ");
    lstrcpyA(output_name, "relay.txt");
#endif
    if (!wide(output_name, output, 32)) return 3;
    if (TOOL_FIXED) {
        if (!CopyFileW(argv[1], output, TRUE)) return 3;
        message("Document collected.\n");
        return 0;
    }
    for (;;) {
        switch (state) {
        case 0x31:
#if TOOL_PROTECTED
            state = ((noise * (noise + 1)) & 1) ? 0xff : 0x74;
#else
            state = 0x74;
#endif
            break;
        case 0x74:
            if (!wide(prefix, command, 1024) || lstrlenW(argv[1]) + lstrlenW(command) + 40 >= 1024)
                return 2;
            lstrcatW(command, argv[1]);
            lstrcatW(command, L" > \"");
            lstrcatW(command, output);
            lstrcatW(command, L"\"");
            state = 0x29;
            break;
        case 0x29:
            result = GetSystemDirectoryW(executable, MAX_PATH);
            if (!result || result + 9 >= MAX_PATH) return 3;
            lstrcatW(executable, L"\\cmd.exe");
            memset(&startup, 0, sizeof(startup));
            memset(&process, 0, sizeof(process));
            startup.cb = sizeof(startup);
            if (!CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                                NULL, NULL, &startup, &process)) return 3;
            CloseHandle(process.hThread);
            if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) {
                TerminateProcess(process.hProcess, 6);
                WaitForSingleObject(process.hProcess, INFINITE);
                CloseHandle(process.hProcess);
                return 6;
            }
            if (!GetExitCodeProcess(process.hProcess, &result)) result = 3;
            CloseHandle(process.hProcess);
            return (int)result;
        default:
            return 3;
        }
    }
}
