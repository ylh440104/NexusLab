#pragma once

namespace nexuslab {

constexpr size_t kResidentAbiSize = 0x38;
constexpr size_t kResidentKinds = 4;
constexpr size_t kResidentNodeSize = 0x58;
constexpr size_t kResidentImageMax = 0x40000;

typedef void* (__cdecl* ResidentDispatchWin)();

struct ResidentAbi {
    unsigned long long size;
    void* fn1;
    void* fn2;
    void* fn3;
    void* fn4;
    void* fn5;
    void* fn6;
};

struct ResidentModule {
    void* image;
    size_t imageLength;
    void* moduleHandle;
    ResidentAbi* abi;
    char imagePath[512];
    unsigned long lastError;
    bool loaded;
    bool abiChecked;
};

void ResidentInit(ResidentModule* resident);

bool ResidentLoad(ResidentModule* resident, const unsigned char* blob, size_t length);

bool ResidentValidate(ResidentModule* resident);

void ResidentUnload(ResidentModule* resident);

void* ResidentGetDispatch(ResidentModule* resident, unsigned int kind, void* contextA,
                          void* contextB);

void* ResidentAllocTable(ResidentModule* resident, const void* source, size_t count);

void ResidentShutdown(ResidentModule* resident);

unsigned long long ResidentActiveCount(ResidentModule* resident);

void ResidentInitCallbackTable(ResidentModule* resident, void** out);

void* ResidentRegisterPending(ResidentModule* resident, void* a, size_t count, void* c);

constexpr unsigned int kKindPrimary = 0;
constexpr unsigned int kKindArray = 1;
constexpr unsigned int kKindSlotB = 2;
constexpr unsigned int kKindSlotA = 3;

unsigned int ResidentKindFromCategory(unsigned int category);

bool ResidentBindTable(ResidentModule* resident, unsigned int kind, void* contextA,
                       void* contextB, void** outTable);

}