#include "hook.h"
#include "protocol.h"
#include "resident.h"
#include "resident_blob.h"
#include "send_path.h"
#include "server.h"

namespace {

nexuslab::ServerContext g_server;
nexuslab::ResidentModule g_resident;
nexuslab::SendRuntime g_send;
nexuslab::SendHook g_sendHook;
nexuslab::SendHook g_loginHook;
nexuslab::SendHook g_recvHook;
nexuslab::SendHook g_testHook;
nexuslab::HookCapture g_sendCapture;
nexuslab::HookCapture g_loginCapture;
nexuslab::HookCapture g_recvCapture;
nexuslab::HookCapture g_testCapture;
volatile LONG g_loginSeen = 0;
HANDLE g_worker = nullptr;
HANDLE g_control = nullptr;
HANDLE g_recv = nullptr;
HANDLE g_writer = nullptr;
HANDLE g_recvPoll = nullptr;
HANDLE g_loginPoll = nullptr;
volatile LONG g_stopping = 0;
volatile LONG g_unloadComplete = 0;
volatile LONG g_sendCaptureSynthetic = 0;

int g_bindAnchorA = 0;
int g_bindAnchorB = 0;

}

extern "C" __declspec(dllexport) unsigned long __cdecl nexuslab_prepare_unload_v1() {
    InterlockedExchange(&g_stopping, 1);
    if (g_server.stopEvent != nullptr) {
        SetEvent(g_server.stopEvent);
    }

    HANDLE worker = g_worker;
    if (worker == nullptr) {
        return g_unloadComplete != 0 ? 0 : 170;
    }

    DWORD waited = WaitForSingleObject(worker, 10000);
    if (waited == WAIT_OBJECT_0) {
        g_unloadComplete = 1;
        return 0;
    }
    if (waited == WAIT_TIMEOUT) {
        return 1460;
    }
    if (waited == WAIT_FAILED) {
        DWORD error = GetLastError();
        if (error != 0) {
            return error;
        }
        return g_unloadComplete != 0 ? 0 : 170;
    }

    return 31;
}

extern "C" __declspec(dllexport) void __cdecl nexuslab_set_login_state(int value) {
    if (g_server.stopEvent == nullptr) {
        return;
    }
    nexuslab::SetLoggedIn(&g_server, value != 0);
}

extern "C" __declspec(dllexport) void __cdecl nexuslab_set_login_uin(long long value) {
    if (g_server.stopEvent == nullptr) {
        return;
    }
    nexuslab::SetLoginState(&g_server, value != 0, static_cast<unsigned long long>(value));
}

extern "C" __declspec(dllexport) int __cdecl nexuslab_resident_state() {
    if (!g_resident.loaded) {
        return -1;
    }
    if (!g_resident.abiChecked) {
        return -2;
    }
    return 1;
}

extern "C" __declspec(dllexport) unsigned __int64 __cdecl nexuslab_resident_active() {
    return nexuslab::ResidentActiveCount(&g_resident);
}

extern "C" __declspec(dllexport) unsigned long __cdecl nexuslab_resident_error() {
    return g_resident.lastError;
}

extern "C" __declspec(dllexport) int __cdecl nexuslab_send_prepare() {
    nexuslab::SendRuntimeInit(&g_send);
    return nexuslab::SendRuntimePrepare(&g_send) ? 1 : 0;
}

extern "C" __declspec(dllexport) int __cdecl nexuslab_send_resolve(const char* name) {
    if (name == nullptr) {
        return -1;
    }

    nexuslab::SendPath path;
    if (!nexuslab::SendResolvePath(&g_send, name, &path)) {
        return -2;
    }

    return path.resolved ? 1 : 0;
}

extern "C" __declspec(dllexport) unsigned long long __cdecl nexuslab_send_target(const char* name) {
    if (name == nullptr) {
        return 0;
    }

    nexuslab::SendPath path;
    if (!nexuslab::SendResolvePath(&g_send, name, &path)) {
        return 0;
    }

    return reinterpret_cast<unsigned long long>(path.target);
}

extern "C" __declspec(dllexport) unsigned long __cdecl nexuslab_send_error() {
    return g_send.lastError;
}

extern "C" __declspec(dllexport) unsigned long __cdecl nexuslab_send_regions() {
    return static_cast<unsigned long>(g_send.locator.regionCount);
}

namespace {

int BindDispatch(void* context, unsigned int kind, unsigned int* outKind,
                 unsigned long long* outValue);

void AppendText(char* buffer, size_t capacity, size_t* used, const char* text) {
    while (text[0] != 0 && *used + 1 < capacity) {
        buffer[*used] = text[0];
        ++(*used);
        ++text;
    }
    buffer[*used] = 0;
}

void AppendHex(char* buffer, size_t capacity, size_t* used, unsigned long long value,
               int minDigits) {
    char digits[16];
    const char* table = "0123456789ABCDEF";
    int count = 0;

    if (value == 0) {
        digits[count] = '0';
        ++count;
    } else {
        while (value != 0 && count < 16) {
            digits[count] = table[value & 0xF];
            value >>= 4;
            ++count;
        }
    }

    while (count < minDigits) {
        digits[count] = '0';
        ++count;
    }

    if (*used + 3 < capacity) {
        buffer[*used] = '0';
        ++(*used);
        buffer[*used] = 'x';
        ++(*used);
    }

    while (count > 0) {
        --count;
        if (*used + 1 >= capacity) {
            break;
        }
        buffer[*used] = digits[count];
        ++(*used);
    }

    buffer[*used] = 0;
}

int LocateFunction(void* context, const char* name, char* outText, size_t textSize,
                   unsigned long long* outTarget, unsigned long* outError) {
    nexuslab::SendRuntime* runtime = static_cast<nexuslab::SendRuntime*>(context);

    if (runtime == nullptr || name == nullptr || outTarget == nullptr || outError == nullptr) {
        return 0;
    }

    nexuslab::SendPath path;
    bool resolved = nexuslab::SendResolvePath(runtime, name, &path);

    if (path.functionStart != nullptr) {
        *outTarget = reinterpret_cast<unsigned long long>(path.functionStart);
    } else {
        *outTarget = reinterpret_cast<unsigned long long>(path.target);
    }
    *outError = resolved ? 0 : path.lastError;

    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;

        unsigned long long base = reinterpret_cast<unsigned long long>(runtime->moduleBase);

        AppendText(outText, textSize, &used, "module=");
        AppendHex(outText, textSize, &used, base, 1);
        AppendText(outText, textSize, &used, " size=");
        AppendHex(outText, textSize, &used, runtime->moduleSize, 1);
        AppendText(outText, textSize, &used, " regions=");
        AppendHex(outText, textSize, &used, runtime->locator.regionCount, 1);
        AppendText(outText, textSize, &used, " rerr=");
        AppendHex(outText, textSize, &used, runtime->lastError, 1);

        AppendText(outText, textSize, &used, " str=");
        AppendHex(outText, textSize, &used,
                  path.stringAddress == nullptr ? 0
                                                : reinterpret_cast<unsigned long long>(path.stringAddress) - base, 1);

        AppendText(outText, textSize, &used, " ref=");
        AppendHex(outText, textSize, &used,
                  path.reference == nullptr ? 0
                                            : reinterpret_cast<unsigned long long>(path.reference) - base, 1);

        AppendText(outText, textSize, &used, " tgt=");
        AppendHex(outText, textSize, &used,
                  path.target == nullptr ? 0
                                         : reinterpret_cast<unsigned long long>(path.target) - base, 1);

        AppendText(outText, textSize, &used, " fn=");
        AppendHex(outText, textSize, &used,
                  path.functionStart == nullptr ? 0
                                                : reinterpret_cast<unsigned long long>(path.functionStart) - base, 1);

        AppendText(outText, textSize, &used, " pro=");
        AppendHex(outText, textSize, &used, path.prologue, 16);

        AppendText(outText, textSize, &used, " hits=");
        AppendHex(outText, textSize, &used, path.referenceCount, 1);

        AppendText(outText, textSize, &used, " err=");
        AppendHex(outText, textSize, &used, path.lastError, 1);
    }

    return resolved ? 1 : 0;
}
int HookInstallByName(void* context, const char* name) {
    nexuslab::SendRuntime* runtime = &g_send;

    if (context != nullptr) {
        runtime = static_cast<nexuslab::SendRuntime*>(context);
    }

    if (name == nullptr) {
        return 0;
    }

    nexuslab::SendPath path;
    bool resolved = nexuslab::SendResolvePath(runtime, name, &path);

    if (!resolved || path.functionStart == nullptr) {
        return 0;
    }

    size_t prologueLength = nexuslab::HookMeasurePrologue(
        path.functionStart, nexuslab::kHookJumpSize, nexuslab::kHookMaxPrologue);

    if (prologueLength == 0) {
        return 0;
    }

    nexuslab::SendHook* hook = &g_sendHook;
    nexuslab::HookCapture* capture = &g_sendCapture;
    size_t registerCount = 4;

    const char* cursor = name;
    const char* login = "LoginRequest";
    const char* recv = "OnRecvMsg";
    bool isLogin = true;
    bool isRecv = true;

    for (size_t index = 0; login[index] != 0 || cursor[index] != 0; ++index) {
        if (login[index] != cursor[index]) {
            isLogin = false;
            break;
        }
    }

    for (size_t index = 0; recv[index] != 0 || cursor[index] != 0; ++index) {
        if (recv[index] != cursor[index]) {
            isRecv = false;
            break;
        }
    }

    if (isLogin) {
        hook = &g_loginHook;
        capture = &g_loginCapture;
        registerCount = 1;
    } else if (isRecv) {
        hook = &g_recvHook;
        capture = &g_recvCapture;
        registerCount = 2;
    }

    bool ok = nexuslab::HookInstall(hook, const_cast<unsigned char*>(path.functionStart),
                                    prologueLength, capture, registerCount);

    return ok ? 1 : 0;
}
int HookStateReport(void* context, char* outText, size_t textSize,
                    unsigned long long* outTarget, unsigned long long* outCount) {
    (void)context;

    unsigned long long target = 0;
    if (g_sendHook.target != nullptr) {
        target = reinterpret_cast<unsigned long long>(g_sendHook.target);
    }

    unsigned long long count = nexuslab::HookCaptureCount(&g_sendCapture);

    if (outTarget != nullptr) {
        *outTarget = target;
    }

    if (outCount != nullptr) {
        *outCount = count;
    }

    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;

        AppendText(outText, textSize, &used, "installed=");
        AppendHex(outText, textSize, &used, g_sendHook.installed ? 1 : 0, 1);

        AppendText(outText, textSize, &used, " target=");
        AppendHex(outText, textSize, &used, target, 1);

        AppendText(outText, textSize, &used, " session=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureSlot(&g_sendCapture, 0), 1);

        AppendText(outText, textSize, &used, " calls=");
        AppendHex(outText, textSize, &used, count, 1);

        AppendText(outText, textSize, &used, " err=");
        AppendHex(outText, textSize, &used, g_sendHook.lastError, 1);

        AppendText(outText, textSize, &used, " req=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureSlot(&g_sendCapture, 1), 1);

        AppendText(outText, textSize, &used, " dat=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureSlot(&g_sendCapture, 2), 1);

        AppendText(outText, textSize, &used, " flg=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureSlot(&g_sendCapture, 3), 1);

        AppendText(outText, textSize, &used, " lgi=");
        AppendHex(outText, textSize, &used, g_loginHook.installed ? 1 : 0, 1);

        AppendText(outText, textSize, &used, " lg0=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureSlot(&g_loginCapture, 0), 1);

        AppendText(outText, textSize, &used, " lgn=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureCount(&g_loginCapture), 1);

        AppendText(outText, textSize, &used, " rci=");
        AppendHex(outText, textSize, &used, g_recvHook.installed ? 1 : 0, 1);

        AppendText(outText, textSize, &used, " rc0=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureSlot(&g_recvCapture, 0), 1);

        AppendText(outText, textSize, &used, " rc1=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureSlot(&g_recvCapture, 1), 1);

        AppendText(outText, textSize, &used, " rcn=");
        AppendHex(outText, textSize, &used,
                  nexuslab::HookCaptureCount(&g_recvCapture), 1);

        unsigned long long recvCount = nexuslab::HookCaptureCount(&g_recvCapture);
        if (recvCount != 0) {
            __try {
                unsigned long long recvBase = nexuslab::HookCaptureSlot(&g_recvCapture, 0);
                if (recvBase != 0) {
                    const unsigned char* base =
                        reinterpret_cast<const unsigned char*>(recvBase);
                    AppendText(outText, textSize, &used, " rd0=");
                    unsigned long long d0 = 0;
                    for (int i = 0; i < 8; ++i) {
                        d0 |= static_cast<unsigned long long>(base[i]) << (i * 8);
                    }
                    AppendHex(outText, textSize, &used, d0, 16);

                    AppendText(outText, textSize, &used, " rd8=");
                    unsigned long long d1 = 0;
                    for (int i = 8; i < 16; ++i) {
                        d1 |= static_cast<unsigned long long>(base[i]) << ((i - 8) * 8);
                    }
                    AppendHex(outText, textSize, &used, d1, 16);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                AppendText(outText, textSize, &used, " rdFault");
            }
        }
    }

    return g_sendHook.installed ? 1 : 0;
}

int SendInvokeByName(void* context, char* outText, size_t textSize,
                     unsigned long long* outResult) {
    (void)context;

    unsigned long long session = nexuslab::HookCaptureSlot(&g_sendCapture, 0);
    unsigned long long request = nexuslab::HookCaptureSlot(&g_sendCapture, 1);
    unsigned long long data = nexuslab::HookCaptureSlot(&g_sendCapture, 2);
    unsigned long long calls = nexuslab::HookCaptureCount(&g_sendCapture);

    if (outResult != nullptr) {
        *outResult = session;
    }

    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;

        AppendText(outText, textSize, &used, "session=");
        AppendHex(outText, textSize, &used, session, 1);

        AppendText(outText, textSize, &used, " calls=");
        AppendHex(outText, textSize, &used, calls, 1);

        AppendText(outText, textSize, &used, " ready=");
        AppendHex(outText, textSize, &used, session != 0 ? 1 : 0, 1);

        if (session != 0 && calls != 0) {
            __try {
                const unsigned char* base =
                    reinterpret_cast<const unsigned char*>(session);

                AppendText(outText, textSize, &used, " s[0]=");
                unsigned long long head0 = 0;
                for (int i = 0; i < 8; ++i) {
                    head0 |= static_cast<unsigned long long>(base[i]) << (i * 8);
                }
                AppendHex(outText, textSize, &used, head0, 16);

                AppendText(outText, textSize, &used, " s[8]=");
                unsigned long long head1 = 0;
                for (int i = 8; i < 16; ++i) {
                    head1 |= static_cast<unsigned long long>(base[i]) << ((i - 8) * 8);
                }
                AppendHex(outText, textSize, &used, head1, 16);

                AppendText(outText, textSize, &used, " s60=");
                unsigned long long field60 = 0;
                for (int i = 0; i < 8; ++i) {
                    field60 |= static_cast<unsigned long long>(base[0x60 + i]) << (i * 8);
                }
                AppendHex(outText, textSize, &used, field60, 16);

                if (request != 0) {
                    const unsigned char* reqBase =
                        reinterpret_cast<const unsigned char*>(request);
                    AppendText(outText, textSize, &used, " r0=");
                    unsigned long long r0 = 0;
                    for (int i = 0; i < 8; ++i) {
                        r0 |= static_cast<unsigned long long>(reqBase[i]) << (i * 8);
                    }
                    AppendHex(outText, textSize, &used, r0, 16);
                }

                if (data != 0) {
                    const unsigned char* dataBase =
                        reinterpret_cast<const unsigned char*>(data);
                    AppendText(outText, textSize, &used, " d0=");
                    unsigned long long d0 = 0;
                    for (int i = 0; i < 8; ++i) {
                        d0 |= static_cast<unsigned long long>(dataBase[i]) << (i * 8);
                    }
                    AppendHex(outText, textSize, &used, d0, 16);

                    AppendText(outText, textSize, &used, " d8=");
                    unsigned long long d1 = 0;
                    for (int i = 8; i < 16; ++i) {
                        d1 |= static_cast<unsigned long long>(dataBase[i]) << ((i - 8) * 8);
                    }
                    AppendHex(outText, textSize, &used, d1, 16);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                AppendText(outText, textSize, &used, " dumpFault");
            }
        }
    }

    return session != 0 ? 1 : 0;
}

int SendAckHandler(void* context, const uint8_t* cmd, uint32_t cmdLength,
                   const uint8_t* body, uint32_t bodyLength) {
    (void)context;
    (void)body;
    (void)bodyLength;

    if (cmd == nullptr || cmdLength == 0 || cmdLength > 200) {
        return 0;
    }

    unsigned long long session = nexuslab::HookCaptureSlot(&g_sendCapture, 0);
    if (session == 0) {
        return 0;
    }

    int loggedIn = InterlockedCompareExchange(&g_server.loggedIn, 1, 1);
    if (loggedIn == 0) {
        return 0;
    }

    return 1;
}

int SendReplyHandler(void* context, int* outError, uint8_t* body, uint32_t bodyCapacity,
                     uint32_t* outBodyLength) {
    (void)context;
    (void)body;
    (void)bodyCapacity;

    if (outError != nullptr) {
        *outError = 0;
    }

    if (outBodyLength != nullptr) {
        *outBodyLength = 0;
    }

    unsigned long long session = nexuslab::HookCaptureSlot(&g_sendCapture, 0);
    unsigned long long request = nexuslab::HookCaptureSlot(&g_sendCapture, 1);
    unsigned long long data = nexuslab::HookCaptureSlot(&g_sendCapture, 2);
    if (session == 0 || request == 0 || data == 0) {
        if (outError != nullptr) {
            *outError = -7;
        }
        return 0;
    }

    if (InterlockedCompareExchange(&g_sendCaptureSynthetic, 1, 1) != 0) {
        if (outError != nullptr) {
            *outError = 0;
        }
        return 1;
    }

    unsigned long long result = 0;
    bool invoked = nexuslab::SendInvokeSend(&g_send, session, request, data, 0, &result);


    if (!invoked) {
        if (outError != nullptr) {
            *outError = -2;
        }
        return 0;
    }

    if (outError != nullptr) {
        *outError = 0;
    }

    return 1;
}

int SendDryRun(void* context, char* outText, size_t textSize,
               unsigned long long* outResult) {
    (void)context;

    unsigned long long session = nexuslab::HookCaptureSlot(&g_sendCapture, 0);
    unsigned long long request = nexuslab::HookCaptureSlot(&g_sendCapture, 1);
    unsigned long long data = nexuslab::HookCaptureSlot(&g_sendCapture, 2);

    if (outResult != nullptr) {
        *outResult = session;
    }

    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;

        AppendText(outText, textSize, &used, "sendPath=");
        AppendHex(outText, textSize, &used,
                  nexuslab::SendRuntimePathCount(&g_send), 1);

        AppendText(outText, textSize, &used, " session=");
        AppendHex(outText, textSize, &used, session, 1);

        AppendText(outText, textSize, &used, " request=");
        AppendHex(outText, textSize, &used, request, 1);

        AppendText(outText, textSize, &used, " data=");
        AppendHex(outText, textSize, &used, data, 1);

        AppendText(outText, textSize, &used, " canSend=");
        AppendHex(outText, textSize, &used,
                  (session != 0 && request != 0 && data != 0) ? 1 : 0, 1);
    }

    return (session != 0 && request != 0 && data != 0) ? 1 : 0;
}

int CaptureTest(void* context, char* outText, size_t textSize,
                unsigned long long* outResult) {
    (void)context;

    if (outResult != nullptr) {
        *outResult = 0;
    }

    unsigned char* code = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (code == nullptr) {
        if (outText != nullptr && textSize > 0) {
            size_t used = 0;
            outText[0] = 0;
            AppendText(outText, textSize, &used, "allocFailed");
        }
        return 0;
    }

    static const unsigned char fake[] = {
        0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x56, 0x57, 0x53, 0x48, 0x81, 0xEC, 0xF8, 0x01, 0x00, 0x00,
        0x48, 0x81, 0xC4, 0xF8, 0x01, 0x00, 0x00,
        0x5B, 0x5F, 0x5E, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
    };

    for (size_t i = 0; i < sizeof(fake); ++i) {
        code[i] = fake[i];
    }

    FlushInstructionCache(GetCurrentProcess(), code, sizeof(fake));

    nexuslab::HookInit(&g_testHook);
    for (size_t i = 0; i < nexuslab::kMaxCapturedSlots; ++i) {
        g_testCapture.slots[i] = 0;
    }
    g_testCapture.count = 0;

    size_t prologue = nexuslab::HookMeasurePrologue(
        code, nexuslab::kHookJumpSize, nexuslab::kHookMaxPrologue);

    bool installed = false;
    if (prologue != 0) {
        installed = nexuslab::HookInstall(&g_testHook, code, prologue, &g_testCapture, 4);
    }

    bool invoked = false;

    if (installed) {
        typedef unsigned long long(__fastcall * TestSignature)(
            unsigned long long, unsigned long long, unsigned long long, unsigned long long);
        TestSignature fn = reinterpret_cast<TestSignature>(code);
        __try {
            fn(0x1122334455667788, 0x234567890ABCDEF1, 0x34567890ABCDEF12, 0x5A);
            invoked = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            invoked = false;
        }
    }

    unsigned long long slot0 = nexuslab::HookCaptureSlot(&g_testCapture, 0);
    unsigned long long slot1 = nexuslab::HookCaptureSlot(&g_testCapture, 1);
    unsigned long long slot2 = nexuslab::HookCaptureSlot(&g_testCapture, 2);
    unsigned long long slot3 = nexuslab::HookCaptureSlot(&g_testCapture, 3);
    unsigned long long count = nexuslab::HookCaptureCount(&g_testCapture);

    bool ok = invoked && installed && count == 1 &&
              slot0 == 0x1122334455667788ull &&
              slot1 == 0x234567890ABCDEF1ull &&
              slot2 == 0x34567890ABCDEF12ull &&
              slot3 == 0x5Aull;

    if (installed) {
        nexuslab::HookUninstall(&g_testHook);
    }

    VirtualFree(code, 0, MEM_RELEASE);

    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;

        AppendText(outText, textSize, &used, "prologue=");
        AppendHex(outText, textSize, &used, prologue, 1);

        AppendText(outText, textSize, &used, " installed=");
        AppendHex(outText, textSize, &used, installed ? 1 : 0, 1);

        AppendText(outText, textSize, &used, " invoked=");
        AppendHex(outText, textSize, &used, invoked ? 1 : 0, 1);

        AppendText(outText, textSize, &used, " count=");
        AppendHex(outText, textSize, &used, count, 1);

        AppendText(outText, textSize, &used, " s0=");
        AppendHex(outText, textSize, &used, slot0, 1);

        AppendText(outText, textSize, &used, " s1=");
        AppendHex(outText, textSize, &used, slot1, 1);

        AppendText(outText, textSize, &used, " s2=");
        AppendHex(outText, textSize, &used, slot2, 1);

        AppendText(outText, textSize, &used, " s3=");
        AppendHex(outText, textSize, &used, slot3, 1);

        AppendText(outText, textSize, &used, " ok=");
        AppendHex(outText, textSize, &used, ok ? 1 : 0, 1);
    }

    if (outResult != nullptr) {
        *outResult = slot0;
    }

    return ok ? 1 : 0;
}

int ReadMemoryHandler(void* context, unsigned long long address, uint8_t* buffer,
                      uint32_t capacity, uint32_t* outLength) {
    (void)context;

    if (buffer == nullptr || outLength == nullptr || capacity == 0 || address == 0) {
        return 0;
    }

    if (capacity > 512) {
        capacity = 512;
    }

    uint32_t length = 0;

    __try {
        const unsigned char* base = reinterpret_cast<const unsigned char*>(address);
        for (uint32_t i = 0; i < capacity; ++i) {
            buffer[i] = base[i];
        }
        length = capacity;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    *outLength = length;
    return 1;
}

int InjectRecvCapture(void* context, char* outText, size_t textSize,
                      unsigned long long* outResult) {
    (void)context;

    if (outResult != nullptr) {
        *outResult = 0;
    }

    void* arrayStruct = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    void* messageData = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    void* contextObject = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);

    if (arrayStruct == nullptr || messageData == nullptr || contextObject == nullptr) {
        if (arrayStruct != nullptr) {
            VirtualFree(arrayStruct, 0, MEM_RELEASE);
        }
        if (messageData != nullptr) {
            VirtualFree(messageData, 0, MEM_RELEASE);
        }
        if (contextObject != nullptr) {
            VirtualFree(contextObject, 0, MEM_RELEASE);
        }
        if (outText != nullptr && textSize > 0) {
            size_t used = 0;
            outText[0] = 0;
            AppendText(outText, textSize, &used, "allocFailed");
        }
        return 0;
    }

    unsigned char* message = static_cast<unsigned char*>(messageData);
    static const char marker[] = "NEXUSLAB_RECV_TEST";
    for (size_t i = 0; i < sizeof(marker); ++i) {
        message[i] = static_cast<unsigned char>(marker[i]);
    }

    unsigned char* arrayBytes = static_cast<unsigned char*>(arrayStruct);
    unsigned long long beginValue = reinterpret_cast<unsigned long long>(messageData);
    unsigned long long endValue = beginValue + 64;
    for (int i = 0; i < 8; ++i) {
        arrayBytes[i] = static_cast<unsigned char>((beginValue >> (i * 8)) & 0xFF);
        arrayBytes[8 + i] = static_cast<unsigned char>((endValue >> (i * 8)) & 0xFF);
    }

    unsigned long long savedContext = nexuslab::HookCaptureSlot(&g_recvCapture, 0);
    unsigned long long savedStruct = nexuslab::HookCaptureSlot(&g_recvCapture, 1);
    unsigned long long savedCount = nexuslab::HookCaptureCount(&g_recvCapture);

    g_recvCapture.slots[0] = static_cast<long long>(
        reinterpret_cast<unsigned long long>(contextObject));
    g_recvCapture.slots[1] = static_cast<long long>(
        reinterpret_cast<unsigned long long>(arrayStruct));
    InterlockedIncrement64(&g_recvCapture.count);

    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;

        AppendText(outText, textSize, &used, "injected=1");

        AppendText(outText, textSize, &used, " array=");
        AppendHex(outText, textSize, &used,
                  reinterpret_cast<unsigned long long>(arrayStruct), 1);

        AppendText(outText, textSize, &used, " msg=");
        AppendHex(outText, textSize, &used,
                  reinterpret_cast<unsigned long long>(messageData), 1);

        AppendText(outText, textSize, &used, " prevCount=");
        AppendHex(outText, textSize, &used, savedCount, 1);
    }

    if (outResult != nullptr) {
        *outResult = reinterpret_cast<unsigned long long>(messageData);
    }

    (void)savedContext;
    (void)savedStruct;

    return 1;
}

int InjectLoginCapture(void* context, char* outText, size_t textSize,
                       unsigned long long* outResult) {
    (void)context;

    if (outResult != nullptr) {
        *outResult = 0;
    }

    void* object = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
    if (object == nullptr) {
        if (outText != nullptr && textSize > 0) {
            size_t used = 0;
            outText[0] = 0;
            AppendText(outText, textSize, &used, "allocFailed");
        }
        return 0;
    }

    unsigned char* bytes = static_cast<unsigned char*>(object);
    unsigned long long fakeUin = 10001;
    for (int i = 0; i < 8; ++i) {
        bytes[i] = static_cast<unsigned char>((fakeUin >> (i * 8)) & 0xFF);
    }

    unsigned long long savedObject = nexuslab::HookCaptureSlot(&g_loginCapture, 0);
    unsigned long long savedCount = nexuslab::HookCaptureCount(&g_loginCapture);

    g_loginCapture.slots[0] = static_cast<long long>(
        reinterpret_cast<unsigned long long>(object));
    InterlockedIncrement64(&g_loginCapture.count);

    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;

        AppendText(outText, textSize, &used, "injected=1");

        AppendText(outText, textSize, &used, " object=");
        AppendHex(outText, textSize, &used,
                  reinterpret_cast<unsigned long long>(object), 1);

        AppendText(outText, textSize, &used, " uin=");
        AppendHex(outText, textSize, &used, fakeUin, 1);

        AppendText(outText, textSize, &used, " prevCount=");
        AppendHex(outText, textSize, &used, savedCount, 1);
    }

    if (outResult != nullptr) {
        *outResult = reinterpret_cast<unsigned long long>(object);
    }

    (void)savedObject;

    return 1;
}

int ResetLoginState(void* context, char* outText, size_t textSize,
                    unsigned long long* outResult) {
    (void)context;
    if (outResult != nullptr) {
        *outResult = 0;
    }
    nexuslab::SetLoginState(&g_server, false, 0);
    g_loginCapture.count = 0;
    g_loginCapture.slots[0] = 0;
    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;
        AppendText(outText, textSize, &used, "reset=1 loggedIn=");
        int state = InterlockedCompareExchange(&g_server.loggedIn, 1, 1);
        AppendHex(outText, textSize, &used, state != 0 ? 1 : 0, 1);
    }
    return 1;
}
int InjectSendCapture(void* context, char* outText, size_t textSize,
                      unsigned long long* outResult) {
    (void)context;
    if (outResult != nullptr) {
        *outResult = 0;
    }
    unsigned long long savedCount = nexuslab::HookCaptureCount(&g_sendCapture);
    g_sendCapture.slots[0] = static_cast<long long>(0x1000);
    g_sendCapture.slots[1] = static_cast<long long>(0x2000);
    g_sendCapture.slots[2] = static_cast<long long>(0x3000);
    InterlockedIncrement64(&g_sendCapture.count);
    InterlockedExchange(&g_sendCaptureSynthetic, 1);
    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;
        AppendText(outText, textSize, &used, "injected=1 synthetic=1 prevCount=");
        AppendHex(outText, textSize, &used, savedCount, 1);
    }
    if (outResult != nullptr) {
        *outResult = 0x1000;
    }
    return 1;
}
int ResetSendCapture(void* context, char* outText, size_t textSize,
                     unsigned long long* outResult) {
    (void)context;
    if (outResult != nullptr) {
        *outResult = 0;
    }
    InterlockedExchange(&g_sendCaptureSynthetic, 0);
    g_sendCapture.count = 0;
    g_sendCapture.slots[0] = 0;
    g_sendCapture.slots[1] = 0;
    g_sendCapture.slots[2] = 0;
    if (outText != nullptr && textSize > 0) {
        size_t used = 0;
        outText[0] = 0;
        AppendText(outText, textSize, &used, "reset=1 synthetic=0");
    }
    return 1;
}

DWORD WINAPI LoginHookPoll(LPVOID parameter) {
    (void)parameter;

    unsigned long long lastCount = 0;

    while (InterlockedCompareExchange(&g_stopping, 0, 0) == 0) {
        Sleep(500);

        unsigned long long count = nexuslab::HookCaptureCount(&g_loginCapture);
        if (count == lastCount || count == 0) {
            continue;
        }

        lastCount = count;

        unsigned long long object = nexuslab::HookCaptureSlot(&g_loginCapture, 0);

        InterlockedExchange(&g_loginSeen, 1);

        if (object != 0) {
            unsigned long long uin = 0;

            __try {
                const unsigned char* base = reinterpret_cast<const unsigned char*>(object);
                for (int i = 0; i < 8; ++i) {
                    uin |= static_cast<unsigned long long>(base[i]) << (i * 8);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                uin = 0;
            }

            if (uin >= 10000ULL && uin <= 999999999999ULL) {
                nexuslab::SetLoginState(&g_server, true, uin);
                nexuslab::EnqueueLoginState(&g_server, true, uin);
            } else {
                nexuslab::SetLoggedIn(&g_server, true);
            }
        }
    }

    return 0;
}
DWORD WINAPI RecvHookPoll(LPVOID parameter) {
    (void)parameter;

    unsigned long long lastCount = 0;

    while (InterlockedCompareExchange(&g_stopping, 0, 0) == 0) {
        Sleep(500);

        unsigned long long count = nexuslab::HookCaptureCount(&g_recvCapture);
        if (count == lastCount || count == 0) {
            continue;
        }

        lastCount = count;

        unsigned long long context = nexuslab::HookCaptureSlot(&g_recvCapture, 0);
        unsigned long long arrayStruct = nexuslab::HookCaptureSlot(&g_recvCapture, 1);

        unsigned long long dumpSource = 0;
        unsigned long long arrayBegin = 0;
        unsigned long long arrayEnd = 0;

        if (arrayStruct != 0) {
            __try {
                const unsigned char* base = reinterpret_cast<const unsigned char*>(arrayStruct);
                for (int i = 0; i < 8; ++i) {
                    arrayBegin |= static_cast<unsigned long long>(base[i]) << (i * 8);
                }
                for (int i = 8; i < 16; ++i) {
                    arrayEnd |= static_cast<unsigned long long>(base[i]) << ((i - 8) * 8);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                arrayBegin = 0;
                arrayEnd = 0;
            }

            if (arrayBegin != 0 && arrayEnd > arrayBegin && (arrayEnd - arrayBegin) <= 0x1000) {
                dumpSource = arrayBegin;
            }
        }

        if (dumpSource == 0) {
            dumpSource = context;
        }

        if (dumpSource == 0) {
            continue;
        }

        unsigned char dump[192];
        size_t dumpLength = 0;

        __try {
            const unsigned char* base = reinterpret_cast<const unsigned char*>(dumpSource);
            for (size_t i = 0; i < sizeof(dump); ++i) {
                dump[i] = base[i];
            }
            dumpLength = sizeof(dump);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dumpLength = 0;
        }

        if (dumpLength == 0) {
            continue;
        }

        char cmd[64];
        size_t cursor = 0;
        const char* prefix = "OnRecvMsg+";
        while (prefix[cursor] != 0 && cursor < sizeof(cmd) - 1) {
            cmd[cursor] = prefix[cursor];
            ++cursor;
        }

        {
            unsigned long long value = arrayStruct;
            char reversed[16];
            int digits = 0;

            if (value == 0) {
                reversed[digits] = '0';
                ++digits;
            } else {
                while (value != 0 && digits < 16) {
                    int nibble = static_cast<int>(value & 0xF);
                    reversed[digits] = static_cast<char>(nibble < 10 ? ('0' + nibble)
                                                                     : ('A' + nibble - 10));
                    value >>= 4;
                    ++digits;
                }
            }

            for (int i = 0; i < digits && cursor < sizeof(cmd) - 1; ++i) {
                cmd[cursor] = reversed[digits - 1 - i];
                ++cursor;
            }
        }
        cmd[cursor] = 0;

        nexuslab::EnqueueRecvPacket(&g_server, 0, cmd, "0", dump, dumpLength);
    }

    return 0;
}

DWORD WINAPI WorkerThread(void* parameter) {
    if (!nexuslab::StartServers(&g_server)) {
        nexuslab::StopServers(&g_server);
        return 1;
    }

    g_server.residentContext = &g_resident;
    g_server.bindDispatch = BindDispatch;
    g_server.locateContext = &g_send;
    g_server.locateFunction = LocateFunction;

    nexuslab::HookInit(&g_sendHook);
    nexuslab::HookInit(&g_loginHook);
    nexuslab::HookInit(&g_recvHook);

    g_server.hookContext = &g_send;
    g_server.hookInstall = HookInstallByName;
    g_server.hookState = HookStateReport;
    g_server.invokeContext = &g_send;
    g_server.sendInvoke = SendInvokeByName;
    g_server.sendDryRun = SendDryRun;
    g_server.captureTest = CaptureTest;
    g_server.readMemory = ReadMemoryHandler;
    g_server.injectRecvCapture = InjectRecvCapture;
    g_server.injectLoginCapture = InjectLoginCapture;
    g_server.resetLoginState = ResetLoginState;
    g_server.injectSendCapture = InjectSendCapture;
    g_server.resetSendCapture = ResetSendCapture;
    g_server.sendAck = SendAckHandler;
    g_server.sendReply = SendReplyHandler;

    g_control = CreateThread(nullptr, 0, nexuslab::ControlThread, &g_server, 0, nullptr);
    g_recv = CreateThread(nullptr, 0, nexuslab::RecvThread, &g_server, 0, nullptr);
    g_writer = CreateThread(nullptr, 0, nexuslab::WriterThread, &g_server, 0, nullptr);
    g_recvPoll = CreateThread(nullptr, 0, RecvHookPoll, nullptr, 0, nullptr);
    g_loginPoll = CreateThread(nullptr, 0, LoginHookPoll, nullptr, 0, nullptr);
    nexuslab::ResidentInit(&g_resident);
    nexuslab::ResidentLoad(&g_resident, kNexuslabResidentImage,
                           static_cast<size_t>(kNexuslabResidentImageSize));
    int residentState = -1;
    if (g_resident.loaded) {
        residentState = g_resident.abiChecked ? 1 : -2;
    }
    InterlockedExchange(&g_server.residentState, residentState);
    InterlockedExchange(&g_server.residentError, static_cast<LONG>(g_resident.lastError));
    g_server.residentActive = nexuslab::ResidentActiveCount(&g_resident);

    while (InterlockedCompareExchange(&g_stopping, 1, 1) == 0) {
        Sleep(100);
    }

    if (g_server.stopEvent != nullptr) {
        SetEvent(g_server.stopEvent);
    }

    if (g_resident.loaded) {
        nexuslab::ResidentShutdown(&g_resident);
        nexuslab::ResidentUnload(&g_resident);
    }

    return 0;
}

void JoinWorker(HANDLE worker) {
    if (worker != nullptr) {
        WaitForSingleObject(worker, 3000);
        CloseHandle(worker);
    }
}

int BindDispatch(void* context, unsigned int kind, unsigned int* outKind,
                 unsigned long long* outValue) {
    nexuslab::ResidentModule* resident = static_cast<nexuslab::ResidentModule*>(context);

    if (resident == nullptr || outKind == nullptr || outValue == nullptr) {
        return 0;
    }

    unsigned int resolved = kind;
    if (resolved > nexuslab::kKindSlotA) {
        return 0;
    }

    *outKind = resolved;

    if (!resident->abiChecked) {
        return 0;
    }

    void* table = nexuslab::ResidentGetDispatch(resident, resolved, &g_bindAnchorA,
                                                &g_bindAnchorB);

    if (table == nullptr) {
        unsigned long err = GetLastError();
        if (err != 0) {
            resident->lastError = err;
            InterlockedExchange(&g_server.residentError, static_cast<LONG>(err));
        }
        return 0;
    }

    *outValue = reinterpret_cast<unsigned long long>(table);
    return 1;
}

}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        nexuslab::ResidentInit(&g_resident);
        g_worker = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
        return TRUE;
    }

    if (reason == DLL_PROCESS_DETACH) {
        if (reserved != nullptr) {
            return TRUE;
        }

        InterlockedExchange(&g_stopping, 1);
        if (g_server.stopEvent != nullptr) {
            SetEvent(g_server.stopEvent);
        }

        JoinWorker(g_worker);
        g_worker = nullptr;
        JoinWorker(g_control);
        g_control = nullptr;
        JoinWorker(g_recv);
        g_recv = nullptr;
        JoinWorker(g_writer);
        g_writer = nullptr;
        JoinWorker(g_recvPoll);
        g_recvPoll = nullptr;
        JoinWorker(g_loginPoll);
        g_loginPoll = nullptr;
        nexuslab::StopServers(&g_server);

        Sleep(5000);
        return TRUE;
    }

    return TRUE;
}