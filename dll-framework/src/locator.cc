#include "locator.h"

#include <windows.h>
#include <tlhelp32.h>

namespace nexuslab {

namespace {

constexpr size_t kRipDispOffset = 3;
constexpr size_t kRipInsnLength = 7;
constexpr size_t kMaxAutoRegions = 512;

struct AutoRegion {
    const unsigned char* base;
    size_t size;
    bool executable;
};

AutoRegion g_autoRegions[kMaxAutoRegions];
size_t g_autoCount = 0;
bool g_autoReady = false;

bool SectionNameEquals(const char* sectionName, const char* expected) {
    for (size_t index = 0; index < 8; ++index) {
        char left = sectionName[index];
        char right = index < 8 ? expected[index] : 0;

        if (right == 0) {
            return left == 0;
        }

        if (left != right) {
            return false;
        }
    }

    return false;
}

void EnsureAutoRegions() {
    if (g_autoReady) {
        return;
    }

    g_autoCount = 0;

    const unsigned char* address = nullptr;
    MEMORY_BASIC_INFORMATION info;

    while (g_autoCount < kMaxAutoRegions) {
        if (VirtualQuery(address, &info, sizeof(info)) == 0) {
            break;
        }

        size_t regionSize = static_cast<size_t>(info.RegionSize);
        if (regionSize == 0) {
            break;
        }

        bool committed = info.State == MEM_COMMIT;
        bool accessible = info.Protect == PAGE_READONLY ||
                          info.Protect == PAGE_READWRITE ||
                          info.Protect == PAGE_WRITECOPY ||
                          info.Protect == PAGE_EXECUTE_READ ||
                          info.Protect == PAGE_EXECUTE_READWRITE ||
                          info.Protect == PAGE_EXECUTE_WRITECOPY;

        if (committed && accessible) {
            bool executable = info.Protect == PAGE_EXECUTE_READ ||
                              info.Protect == PAGE_EXECUTE_READWRITE ||
                              info.Protect == PAGE_EXECUTE_WRITECOPY;

            g_autoRegions[g_autoCount].base =
                static_cast<const unsigned char*>(info.BaseAddress);
            g_autoRegions[g_autoCount].size = regionSize;
            g_autoRegions[g_autoCount].executable = executable;
            ++g_autoCount;
        }

        address = static_cast<const unsigned char*>(info.BaseAddress) + regionSize;

        if (reinterpret_cast<unsigned long long>(address) <
            reinterpret_cast<unsigned long long>(info.BaseAddress)) {
            break;
        }
    }

    g_autoReady = true;
}

}

void LocatorInit(LocatorContext* ctx) {
    ctx->regionCount = 0;
    ctx->lastError = 0;
    ctx->totalScanned = 0;
    ctx->totalMatches = 0;
}

bool LocatorAddRegion(LocatorContext* ctx, const void* base, size_t size, bool executable) {
    if (ctx->regionCount >= sizeof(ctx->regions) / sizeof(ctx->regions[0])) {
        ctx->lastError = 122;
        return false;
    }

    if (base == nullptr || size == 0) {
        ctx->lastError = 87;
        return false;
    }

    ctx->regions[ctx->regionCount].base = static_cast<const unsigned char*>(base);
    ctx->regions[ctx->regionCount].size = size;
    ctx->regions[ctx->regionCount].executable = executable;
    ++ctx->regionCount;

    return true;
}

bool LocatorAddModuleRegion(LocatorContext* ctx, const char* moduleName, bool executable) {
    void* base = LocatorFindModuleBase(moduleName);
    if (base == nullptr) {
        ctx->lastError = 126;
        return false;
    }

    size_t size = LocatorReadModuleSize(moduleName, base);
    if (size == 0) {
        ctx->lastError = 13;
        return false;
    }

    return LocatorAddRegion(ctx, base, size, executable);
}

size_t LocatorFindString(const LocatorContext* ctx, const char* text, size_t length,
                         const unsigned char** outAddresses, size_t maxAddresses) {
    if (text == nullptr || length == 0 || length > kMaxPatternLength) {
        return 0;
    }

    if (outAddresses == nullptr || maxAddresses == 0) {
        return 0;
    }

    size_t found = 0;

    for (size_t regionIndex = 0; regionIndex < ctx->regionCount; ++regionIndex) {
        const ScanRegion& region = ctx->regions[regionIndex];

        if (region.executable || region.size < length) {
            continue;
        }

        const unsigned char* cursor = region.base;
        const unsigned char* limit = region.base + region.size - length;

        while (cursor <= limit) {
            if (cursor[0] != static_cast<unsigned char>(text[0])) {
                ++cursor;
                continue;
            }

            bool boundaryOk = true;
            if (cursor != region.base && cursor[-1] != 0) {
                boundaryOk = false;
            }

            if (!boundaryOk) {
                ++cursor;
                continue;
            }

            bool matched = true;
            for (size_t index = 1; index < length; ++index) {
                if (cursor[index] != static_cast<unsigned char>(text[index])) {
                    matched = false;
                    break;
                }
            }

            if (!matched) {
                ++cursor;
                continue;
            }

            outAddresses[found] = cursor;
            ++found;

            if (found >= maxAddresses) {
                return found;
            }

            cursor += length;
        }
    }

    return found;
}

const unsigned char* LocatorFindReference(const LocatorContext* ctx,
                                          const unsigned char* stringAddress) {
    if (stringAddress == nullptr) {
        return nullptr;
    }

    for (size_t regionIndex = 0; regionIndex < ctx->regionCount; ++regionIndex) {
        const ScanRegion& region = ctx->regions[regionIndex];

        if (!region.executable || region.size < kRipInsnLength) {
            continue;
        }

        const unsigned char* cursor = region.base;
        const unsigned char* limit = region.base + region.size - kRipInsnLength;

        while (cursor <= limit) {
            unsigned char byte0 = cursor[0];

            if (byte0 != 0x48 && byte0 != 0x4C) {
                ++cursor;
                continue;
            }

            if (cursor[1] != 0x8D) {
                ++cursor;
                continue;
            }

            unsigned char modrm = cursor[2];
            if ((modrm & 0xC7) != 0x05) {
                ++cursor;
                continue;
            }

            int displacement = 0;
            for (size_t index = 0; index < 4; ++index) {
                displacement |= static_cast<int>(cursor[kRipDispOffset + index]) << (index * 8);
            }

            const unsigned char* target = cursor + kRipInsnLength + displacement;

            if (target == stringAddress) {
                return cursor;
            }

            ++cursor;
        }
    }

    return nullptr;
}

bool LocatorResolve(const LocatorContext* ctx, const char* text, size_t length,
                    ScanResult* outResult) {
    if (outResult == nullptr) {
        return false;
    }

    outResult->stringAddress = nullptr;
    outResult->referenceAddress = nullptr;
    outResult->referenceCount = 0;

    const unsigned char* addresses[kMaxScanResults];
    size_t count = LocatorFindString(ctx, text, length, addresses, kMaxScanResults);

    if (count == 0) {
        return false;
    }

    for (size_t index = 0; index < count; ++index) {
        const unsigned char* reference = LocatorFindReference(ctx, addresses[index]);

        if (reference != nullptr) {
            outResult->stringAddress = addresses[index];
            outResult->referenceAddress = reference;
            outResult->referenceCount = count;
            return true;
        }
    }

    outResult->stringAddress = addresses[0];
    outResult->referenceCount = count;

    return false;
}

const unsigned char* LocatorResolveCallable(const LocatorContext* ctx, const char* text,
                                            size_t length) {
    ScanResult result;
    LocatorResolve(ctx, text, length, &result);

    if (result.referenceAddress == nullptr) {
        return nullptr;
    }

    int displacement = 0;
    for (size_t index = 0; index < 4; ++index) {
        displacement |= static_cast<int>(result.referenceAddress[kRipDispOffset + index])
                        << (index * 8);
    }

    return result.referenceAddress + kRipInsnLength + displacement;
}

void* LocatorFindModuleBase(const char* moduleName) {
    if (moduleName == nullptr) {
        return nullptr;
    }

    HMODULE module = GetModuleHandleA(moduleName);
    if (module == nullptr) {
        return nullptr;
    }

    return reinterpret_cast<void*>(module);
}

size_t LocatorReadModuleSize(const char* moduleName, void* base) {
    if (base == nullptr) {
        return 0;
    }

    const unsigned char* image = static_cast<const unsigned char*>(base);

    __try {
        unsigned long peOffset = *reinterpret_cast<const unsigned long*>(image + 0x3C);
        const unsigned char* ntHeader = image + peOffset;

        if (ntHeader[0] != 'P' || ntHeader[1] != 'E') {
            return 0;
        }

        unsigned long sizeOfImage =
            *reinterpret_cast<const unsigned long*>(ntHeader + 0x18 + 0x38);

        return static_cast<size_t>(sizeOfImage);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

void LocatorLoadSelfRegions(LocatorContext* ctx) {
    EnsureAutoRegions();

    size_t added = 0;
    for (size_t index = 0; index < g_autoCount; ++index) {
        if (LocatorAddRegion(ctx, g_autoRegions[index].base, g_autoRegions[index].size,
                             g_autoRegions[index].executable)) {
            ++added;
        }
    }

    (void)added;
}

size_t LocatorAutoRegionCount() {
    EnsureAutoRegions();
    return g_autoCount;
}

size_t LocatorSnapshotModuleSize(const char* moduleName, void** outBase) {
    if (moduleName == nullptr) {
        return 0;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32W entry;
    entry.dwSize = sizeof(entry);

    size_t result = 0;

    if (Module32FirstW(snapshot, &entry)) {
        do {
            char narrow[256];
            size_t index = 0;

            while (entry.szModule[index] != 0 && index + 1 < sizeof(narrow)) {
                wchar_t wide = entry.szModule[index];
                narrow[index] = wide < 0x80 ? static_cast<char>(wide) : '?';
                ++index;
            }
            narrow[index] = 0;

            bool same = true;
            size_t probe = 0;
            while (moduleName[probe] != 0 || narrow[probe] != 0) {
                char left = moduleName[probe];
                char right = narrow[probe];

                if (left >= 'A' && left <= 'Z') {
                    left = static_cast<char>(left - 'A' + 'a');
                }
                if (right >= 'A' && right <= 'Z') {
                    right = static_cast<char>(right - 'A' + 'a');
                }

                if (left != right) {
                    same = false;
                    break;
                }

                ++probe;
            }

            if (same) {
                result = static_cast<size_t>(entry.modBaseSize);
                if (outBase != nullptr) {
                    *outBase = reinterpret_cast<void*>(entry.modBaseAddr);
                }
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    return result;
}

size_t LocatorFindAllReferences(const LocatorContext* ctx,
                                const unsigned char** stringAddresses, size_t stringCount,
                                const unsigned char** outReferences, size_t* outIndices,
                                size_t maxReferences) {
    if (stringAddresses == nullptr || stringCount == 0) {
        return 0;
    }

    if (outReferences == nullptr || maxReferences == 0) {
        return 0;
    }

    size_t found = 0;

    for (size_t regionIndex = 0; regionIndex < ctx->regionCount; ++regionIndex) {
        const ScanRegion& region = ctx->regions[regionIndex];

        if (!region.executable || region.size < kRipInsnLength) {
            continue;
        }

        const unsigned char* cursor = region.base;
        const unsigned char* limit = region.base + region.size - kRipInsnLength;

        while (cursor <= limit) {
            unsigned char byte0 = cursor[0];

            if (byte0 != 0x48 && byte0 != 0x4C) {
                ++cursor;
                continue;
            }

            if (cursor[1] != 0x8D) {
                ++cursor;
                continue;
            }

            if ((cursor[2] & 0xC7) != 0x05) {
                ++cursor;
                continue;
            }

            int displacement = 0;
            for (size_t index = 0; index < 4; ++index) {
                displacement |= static_cast<int>(cursor[kRipDispOffset + index]) << (index * 8);
            }

            const unsigned char* target = cursor + kRipInsnLength + displacement;

            for (size_t index = 0; index < stringCount; ++index) {
                if (target == stringAddresses[index]) {
                    outReferences[found] = cursor;
                    if (outIndices != nullptr) {
                        outIndices[found] = index;
                    }
                    ++found;

                    if (found >= maxReferences) {
                        return found;
                    }

                    break;
                }
            }

            ++cursor;
        }
    }

    return found;
}

const unsigned char* LocatorFindFunctionStart(void* moduleBase, size_t imageSize,
                                              const unsigned char* insideAddress) {
    if (moduleBase == nullptr || insideAddress == nullptr || imageSize < 0x1000) {
        return nullptr;
    }

    const unsigned char* image = static_cast<const unsigned char*>(moduleBase);
    size_t insideRva = static_cast<size_t>(insideAddress - image);

    if (insideRva >= imageSize) {
        return nullptr;
    }

    __try {
        unsigned long peOffset = *reinterpret_cast<const unsigned long*>(image + 0x3C);
        const unsigned char* ntHeader = image + peOffset;

        if (ntHeader[0] != 'P' || ntHeader[1] != 'E') {
            return nullptr;
        }

        unsigned short sectionCount = *reinterpret_cast<const unsigned short*>(ntHeader + 6);
        unsigned short optionalSize = *reinterpret_cast<const unsigned short*>(ntHeader + 0x14);
        const unsigned char* sectionTable = ntHeader + 0x18 + optionalSize;

        const unsigned char* pdataBase = nullptr;
        size_t pdataSize = 0;

        for (unsigned short index = 0; index < sectionCount; ++index) {
            const unsigned char* entry = sectionTable + index * 40;
            const char* name = reinterpret_cast<const char*>(entry);

            if (SectionNameEquals(name, ".pdata")) {
                unsigned long virtualSize = *reinterpret_cast<const unsigned long*>(entry + 8);
                unsigned long virtualAddress = *reinterpret_cast<const unsigned long*>(entry + 12);
                pdataBase = image + virtualAddress;
                pdataSize = virtualSize;
                break;
            }
        }

        if (pdataBase == nullptr || pdataSize < 12) {
            return nullptr;
        }

        size_t count = pdataSize / 12;
        size_t low = 0;
        size_t high = count;

        while (low < high) {
            size_t mid = (low + high) / 2;
            const unsigned char* item = pdataBase + mid * 12;
            unsigned long beginRva = *reinterpret_cast<const unsigned long*>(item);
            unsigned long endRva = *reinterpret_cast<const unsigned long*>(item + 4);

            if (insideRva < beginRva) {
                high = mid;
            } else if (insideRva >= endRva) {
                low = mid + 1;
            } else {
                return image + beginRva;
            }
        }

        return nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

bool LocatorAddModuleSections(LocatorContext* ctx, void* base, size_t imageSize) {
    if (base == nullptr || imageSize < 0x1000) {
        ctx->lastError = 87;
        return false;
    }

    const unsigned char* image = static_cast<const unsigned char*>(base);

    __try {
        unsigned long peOffset = *reinterpret_cast<const unsigned long*>(image + 0x3C);
        const unsigned char* ntHeader = image + peOffset;

        if (ntHeader[0] != 'P' || ntHeader[1] != 'E') {
            ctx->lastError = 11;
            return false;
        }

        unsigned short sectionCount =
            *reinterpret_cast<const unsigned short*>(ntHeader + 6);
        unsigned short optionalSize =
            *reinterpret_cast<const unsigned short*>(ntHeader + 0x14);

        const unsigned char* sectionTable = ntHeader + 0x18 + optionalSize;

        bool anyAdded = false;

        for (unsigned short index = 0; index < sectionCount; ++index) {
            const unsigned char* entry = sectionTable + index * 40;

            const char* sectionName = reinterpret_cast<const char*>(entry);

            bool isText = SectionNameEquals(sectionName, ".text");
            bool isRdata = SectionNameEquals(sectionName, ".rdata");
            bool isData = SectionNameEquals(sectionName, ".data");

            if (!isText && !isRdata && !isData) {
                continue;
            }

            unsigned long virtualSize =
                *reinterpret_cast<const unsigned long*>(entry + 8);
            unsigned long virtualAddress =
                *reinterpret_cast<const unsigned long*>(entry + 12);
            unsigned long rawSize =
                *reinterpret_cast<const unsigned long*>(entry + 16);

            if (virtualSize == 0) {
                continue;
            }

            if (virtualAddress >= imageSize) {
                continue;
            }

            size_t available = imageSize - virtualAddress;
            size_t regionSize = virtualSize;

            if (regionSize > rawSize && rawSize != 0) {
                regionSize = rawSize;
            }

            if (regionSize > available) {
                regionSize = available;
            }

            if (regionSize == 0) {
                continue;
            }

            if (LocatorAddRegion(ctx, image + virtualAddress, regionSize, isText)) {
                anyAdded = true;
            }
        }

        return anyAdded;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ctx->lastError = 11;
        return false;
    }
}

}