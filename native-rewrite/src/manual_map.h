#ifndef NEXUSLAB_MANUAL_MAP_H
#define NEXUSLAB_MANUAL_MAP_H

#include <windows.h>
#include <cstdint>
#include <string>

namespace mmap {

struct Handle {
    uint64_t base;
    uint64_t entry;
    uint64_t exceptionTable;
    uint64_t prepare;
    uint64_t size;
};

struct Result {
    bool ok;
    Handle handle;
    std::string error;
    DWORD lastError;
};

struct UnloadResult {
    bool ok;
    std::string error;
    DWORD lastError;
};

Result Inject(DWORD pid, const std::wstring& dllPath);

UnloadResult Unload(DWORD pid, const Handle& handle);

}

#endif