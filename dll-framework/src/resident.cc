#include "resident.h"

#include <windows.h>

namespace nexuslab {

namespace {

constexpr unsigned long kErrorInvalidParameter = 87;
constexpr unsigned long kErrorNotEnoughMemory = 8;
constexpr unsigned long kErrorAlreadyExists = 183;
constexpr unsigned long kErrorShutdown = 1115;
constexpr unsigned long long kShutdownBit = 0x8000000000000000ULL;
constexpr size_t kTempPathCapacity = 0x105;

typedef void* (__cdecl* FnDispatch)(unsigned int, void*, void*);
typedef void* (__cdecl* FnAlloc)(void*, unsigned long long);
typedef void (__cdecl* FnShutdown)(void);
typedef unsigned long long(__cdecl* FnCount)(void);
typedef void (__cdecl* FnInitCallbacks)(void**);
typedef void* (__cdecl* FnRegister)(void*, unsigned long long, void*, void**);

size_t TextLength(const char* text) {
    size_t count = 0;
    while (text[count] != 0) {
        ++count;
    }
    return count;
}

void AppendText(char* buffer, size_t capacity, size_t* cursor, const char* text) {
    size_t length = TextLength(text);
    for (size_t i = 0; i < length && *cursor + 1 < capacity; ++i) {
        buffer[*cursor] = text[i];
        ++(*cursor);
    }
    buffer[*cursor] = 0;
}

void AppendNumber(char* buffer, size_t capacity, size_t* cursor, unsigned long value) {
    char digits[16];
    size_t count = 0;
    if (value == 0) {
        digits[count++] = '0';
    } else {
        while (value != 0 && count < sizeof(digits)) {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        }
    }
    while (count != 0) {
        --count;
        if (*cursor + 1 < capacity) {
            buffer[*cursor] = digits[count];
            ++(*cursor);
        }
    }
    buffer[*cursor] = 0;
}

bool BuildImagePath(ResidentModule* resident) {
    wchar_t widePath[kTempPathCapacity];
    DWORD length = GetTempPathW(kTempPathCapacity, widePath);
    if (length == 0 || length >= kTempPathCapacity) {
        resident->lastError = GetLastError();
        return false;
    }

    size_t cursor = 0;
    for (DWORD i = 0; i < length && cursor + 1 < sizeof(resident->imagePath); ++i) {
        wchar_t ch = widePath[i];
        if (ch < 0x80) {
            resident->imagePath[cursor++] = static_cast<char>(ch);
        } else {
            resident->imagePath[cursor++] = '_';
        }
    }
    resident->imagePath[cursor] = 0;

    AppendText(resident->imagePath, sizeof(resident->imagePath), &cursor, "nnp_resident_");
    AppendNumber(resident->imagePath, sizeof(resident->imagePath), &cursor,
                 static_cast<unsigned long>(GetCurrentProcessId()));
    AppendText(resident->imagePath, sizeof(resident->imagePath), &cursor, ".dll");

    return cursor != 0;
}

bool WriteImage(const ResidentModule* resident, const unsigned char* blob, size_t length) {
    HANDLE file = CreateFileA(resident->imagePath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    size_t remaining = length;
    const unsigned char* cursor = blob;
    bool ok = true;

    while (remaining != 0) {
        DWORD chunk = static_cast<DWORD>(remaining < 0x10000 ? remaining : 0x10000);
        DWORD written = 0;
        if (!WriteFile(file, cursor, chunk, &written, nullptr) || written == 0) {
            ok = false;
            break;
        }
        cursor += written;
        remaining -= written;
    }

    CloseHandle(file);

    if (!ok) {
        DeleteFileA(resident->imagePath);
    }

    return ok;
}

void RemoveImage(const ResidentModule* resident) {
    if (resident->imagePath[0] != 0) {
        DeleteFileA(resident->imagePath);
    }
}

}

void ResidentInit(ResidentModule* resident) {
    resident->image = nullptr;
    resident->imageLength = 0;
    resident->moduleHandle = nullptr;
    resident->abi = nullptr;
    resident->imagePath[0] = 0;
    resident->lastError = 0;
    resident->loaded = false;
    resident->abiChecked = false;
}

bool ResidentLoad(ResidentModule* resident, const unsigned char* blob, size_t length) {
    if (resident->loaded) {
        return true;
    }

    if (blob == nullptr || length < 2 || blob[0] != 'M' || blob[1] != 'Z') {
        resident->lastError = kErrorInvalidParameter;
        return false;
    }

    if (length > kResidentImageMax) {
        resident->lastError = kErrorInvalidParameter;
        return false;
    }

    if (!BuildImagePath(resident)) {
        return false;
    }

    if (!WriteImage(resident, blob, length)) {
        resident->lastError = GetLastError();
        RemoveImage(resident);
        return false;
    }

    HMODULE module = LoadLibraryExA(resident->imagePath, nullptr, 0x00000800);
    if (module == nullptr) {
        resident->lastError = GetLastError();
        RemoveImage(resident);
        return false;
    }

    resident->moduleHandle = module;

    FARPROC entry = GetProcAddress(module, "nnp_resident_dispatch_win");
    if (entry == nullptr) {
        resident->lastError = GetLastError();
        FreeLibrary(module);
        resident->moduleHandle = nullptr;
        RemoveImage(resident);
        return false;
    }

    ResidentDispatchWin dispatch = reinterpret_cast<ResidentDispatchWin>(entry);
    void* table = dispatch();
    if (table == nullptr) {
        resident->lastError = GetLastError();
        FreeLibrary(module);
        resident->moduleHandle = nullptr;
        RemoveImage(resident);
        return false;
    }

    resident->abi = static_cast<ResidentAbi*>(table);
    resident->loaded = true;

    if (!ResidentValidate(resident)) {
        ResidentUnload(resident);
        return false;
    }

    return true;
}

bool ResidentValidate(ResidentModule* resident) {
    if (!resident->loaded || resident->abi == nullptr) {
        resident->lastError = kErrorInvalidParameter;
        return false;
    }

    ResidentAbi* abi = resident->abi;

    if (abi->size != kResidentAbiSize || abi->fn1 == nullptr || abi->fn2 == nullptr ||
        abi->fn3 == nullptr || abi->fn4 == nullptr || abi->fn5 == nullptr ||
        abi->fn6 == nullptr) {
        resident->lastError = kErrorInvalidParameter;
        resident->abiChecked = false;
        return false;
    }

    resident->abiChecked = true;
    return true;
}

void ResidentUnload(ResidentModule* resident) {
    if (resident->moduleHandle != nullptr) {
        FreeLibrary(static_cast<HMODULE>(resident->moduleHandle));
        resident->moduleHandle = nullptr;
    }

    RemoveImage(resident);

    resident->abi = nullptr;
    resident->loaded = false;
    resident->abiChecked = false;
}

void* ResidentGetDispatch(ResidentModule* resident, unsigned int kind, void* contextA,
                          void* contextB) {
    if (!resident->abiChecked) {
        SetLastError(kErrorInvalidParameter);
        return nullptr;
    }

    FnDispatch fn = reinterpret_cast<FnDispatch>(resident->abi->fn1);
    return fn(kind, contextA, contextB);
}

void* ResidentAllocTable(ResidentModule* resident, const void* source, size_t count) {
    if (!resident->abiChecked) {
        SetLastError(kErrorInvalidParameter);
        return nullptr;
    }

    FnAlloc fn = reinterpret_cast<FnAlloc>(resident->abi->fn2);
    return fn(const_cast<void*>(source), static_cast<unsigned long long>(count));
}

void ResidentShutdown(ResidentModule* resident) {
    if (!resident->abiChecked) {
        return;
    }

    FnShutdown fn = reinterpret_cast<FnShutdown>(resident->abi->fn3);
    fn();
}

unsigned long long ResidentActiveCount(ResidentModule* resident) {
    if (!resident->abiChecked) {
        return 0;
    }

    FnCount fn = reinterpret_cast<FnCount>(resident->abi->fn4);
    return fn();
}

void ResidentInitCallbackTable(ResidentModule* resident, void** out) {
    if (!resident->abiChecked || out == nullptr) {
        return;
    }

    FnInitCallbacks fn = reinterpret_cast<FnInitCallbacks>(resident->abi->fn5);
    fn(out);
}

void* ResidentRegisterPending(ResidentModule* resident, void* a, size_t count, void* c) {
    if (!resident->abiChecked) {
        SetLastError(kErrorInvalidParameter);
        return nullptr;
    }

    void* out = nullptr;
    FnRegister fn = reinterpret_cast<FnRegister>(resident->abi->fn6);
    fn(a, static_cast<unsigned long long>(count), c, &out);
    return out;
}

unsigned int ResidentKindFromCategory(unsigned int category) {
    if (category == 2) {
        return kKindSlotB;
    }
    return kKindSlotA;
}

bool ResidentBindTable(ResidentModule* resident, unsigned int kind, void* contextA,
                       void* contextB, void** outTable) {
    if (outTable == nullptr) {
        SetLastError(kErrorInvalidParameter);
        return false;
    }

    *outTable = ResidentGetDispatch(resident, kind, contextA, contextB);

    if (*outTable == nullptr) {
        unsigned long err = GetLastError();
        if (err == kErrorAlreadyExists || err == kErrorShutdown) {
            resident->lastError = err;
        }
        return false;
    }

    return true;
}

}