#pragma once
#include <windows.h>
namespace nexuslab {

constexpr size_t kHookJumpSize = 14;
constexpr size_t kHookMaxPrologue = 32;
constexpr size_t kMaxCapturedSlots = 8;
constexpr size_t kMaxHookSlots = 8;

struct HookCapture {
    volatile long long slots[kMaxCapturedSlots];
    volatile long long count;
    unsigned char bytesA[24];
    unsigned char bytesB[24];
};

typedef void (*HookHandler)(unsigned long long a, unsigned long long b,
                            unsigned long long c, unsigned long long d);

struct SendHook {
    unsigned char* target;
    unsigned char* trampoline;
    size_t patchLength;
    size_t trampolineLength;
    unsigned char savedBytes[kHookMaxPrologue];
    HookCapture* capture;
    HookHandler handler;
    bool installed;
    unsigned long lastError;
};

size_t HookMeasurePrologue(const unsigned char* code, size_t minimum, size_t limit);
void HookInit(SendHook* hook);
bool HookInstall(SendHook* hook, void* targetAddress, size_t prologueLength,
                 HookCapture* capture, size_t registerCount);
bool HookUninstall(SendHook* hook);
unsigned long long HookCaptureSlot(const HookCapture* capture, size_t index);
unsigned long long HookCaptureCount(const HookCapture* capture);

}