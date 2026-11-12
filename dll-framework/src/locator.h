#pragma once

namespace nexuslab {

constexpr size_t kMaxPatternLength = 128;
constexpr size_t kMaxScanResults = 32;
constexpr size_t kMaxModuleNameLength = 64;

struct PatternSpec {
    const char* text;
    size_t length;
};

struct ScanRegion {
    const unsigned char* base;
    size_t size;
    bool executable;
};

struct ScanResult {
    const unsigned char* stringAddress;
    const unsigned char* referenceAddress;
    size_t referenceCount;
};

struct LocatorContext {
    ScanRegion regions[512];
    size_t regionCount;
    unsigned long lastError;
    size_t totalScanned;
    size_t totalMatches;
};

void LocatorInit(LocatorContext* ctx);

bool LocatorAddRegion(LocatorContext* ctx, const void* base, size_t size, bool executable);

bool LocatorAddModuleRegion(LocatorContext* ctx, const char* moduleName, bool executable);

size_t LocatorFindString(const LocatorContext* ctx, const char* text, size_t length,
                         const unsigned char** outAddresses, size_t maxAddresses);

const unsigned char* LocatorFindReference(const LocatorContext* ctx,
                                          const unsigned char* stringAddress);

bool LocatorResolve(const LocatorContext* ctx, const char* text, size_t length,
                    ScanResult* outResult);

const unsigned char* LocatorResolveCallable(const LocatorContext* ctx, const char* text,
                                            size_t length);

void* LocatorFindModuleBase(const char* moduleName);

size_t LocatorReadModuleSize(const char* moduleName, void* base);

void LocatorLoadSelfRegions(LocatorContext* ctx);

size_t LocatorAutoRegionCount();

bool LocatorAddModuleSections(LocatorContext* ctx, void* base, size_t imageSize);

size_t LocatorSnapshotModuleSize(const char* moduleName, void** outBase);

const unsigned char* LocatorFindFunctionStart(void* moduleBase, size_t imageSize,
                                              const unsigned char* insideAddress);

size_t LocatorFindAllReferences(const LocatorContext* ctx,
                                const unsigned char** stringAddresses, size_t stringCount,
                                const unsigned char** outReferences, size_t* outIndices,
                                size_t maxReferences);

}