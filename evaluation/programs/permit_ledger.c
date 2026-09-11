#include "native_tool.h"

static int tool_main(int argc, WCHAR **argv) {
    unsigned char account[256];
    DWORD length = 0;
    char user[64], password[64], requested_role[64], privilege[16];
    char *stored_password = NULL, *stored_role = NULL;
    unsigned index;
    unsigned state = 0x17;
    volatile DWORD noise = GetCurrentProcessId();
    if (argc != 8) {
        message("PermitLedger 1.0\nUsage: PermitLedger.exe ACCOUNT USER PASSWORD ROLE ACTION RECORD OUTPUT\n");
        return 2;
    }
    if (!read_bytes(argv[1], account, sizeof(account) - 1, &length) || !length ||
        !utf8(argv[2], user, sizeof(user)) || !utf8(argv[3], password, sizeof(password)) ||
        !utf8(argv[4], requested_role, sizeof(requested_role))) return 2;
    account[length] = 0;
    for (index = 0; index < length; ++index) {
        if (account[index] == '\r' || account[index] == '\n') account[index] = 0;
        if (account[index] == '|') {
            account[index] = 0;
            if (!stored_password) stored_password = (char *)account + index + 1;
            else if (!stored_role) stored_role = (char *)account + index + 1;
            else return 2;
        }
    }
    if (!stored_password || !stored_role) return 2;
#if TOOL_PROTECTED
    {
        static const unsigned char data[] = {59, 62, 55, 51, 52};
        reveal(data, sizeof(data), 0x5a, privilege);
    }
#else
    lstrcpyA(privilege, "admin");
#endif
    for (;;) {
        switch (state) {
        case 0x17:
#if TOOL_PROTECTED
            state = ((noise * (noise + 1)) & 1) ? 0xee : 0x92;
#else
            state = 0x92;
#endif
            break;
        case 0x92:
            if (lstrcmpA(user, (char *)account) || lstrcmpA(password, stored_password)) {
                message("Authentication failed.\n");
                return 5;
            }
            if (!lstrcmpW(argv[5], L"status")) {
                message("Account authenticated.\n");
                return 0;
            }
            if (lstrcmpW(argv[5], L"export")) return 2;
            state = 0x43;
            break;
        case 0x43:
            if (lstrcmpA(TOOL_FIXED ? stored_role : requested_role, privilege)) {
                message("Export denied.\n");
                // The corrected build refuses the export and completes normally.
                return TOOL_FIXED ? 0 : 4;
            }
            state = 0xb8;
            break;
        case 0xb8:
            if (!CopyFileW(argv[6], argv[7], TRUE)) return 3;
            message("Record exported.\n");
            return 0;
        default:
            return 3;
        }
    }
}
