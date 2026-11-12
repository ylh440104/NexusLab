#include "send_path.h"

#include <windows.h>

namespace nexuslab {
namespace {

constexpr const char* kSendFunction = "SendSSORequestInternal";
constexpr const char* kLoginFunction = "OnLoginSuccess";
constexpr const char* kRequestFunction = "LoginRequest";
constexpr const char* kMsfService = ".?AVMSFService@nt@@";
constexpr const char* kMsfCoreService = ".?AVMSFCoreService@nt@@";
constexpr const char* kLoginFull = "LoginRequest OnLoginSuccess uin:";
constexpr const char* kRecvFunction = "OnRecvMsg";
constexpr const char* kRecvAltFunction = "RecvMsg";
constexpr size_t kMaxScannableBytes = 512u * 1024u * 1024u;
constexpr size_t kKnownFunctionCount = 8;
constexpr size_t kMaxStringHits = 16;
constexpr size_t kMaxReferenceHits = 96;
const char* const kKnownFunctions[kKnownFunctionCount] = {
    kSendFunction,
    kLoginFunction,
    kRequestFunction,
    kMsfService,
    kMsfCoreService,
    kLoginFull,
    kRecvFunction,
    kRecvAltFunction,
};

size_t TextLength(const char* text) {
    size_t count = 0;
    while (text[count] != 0) {
        ++count;
    }
    return count;
}

void CopyText(char* target, const char* source, size_t capacity) {
    size_t index = 0;
    while (source[index] != 0 && index + 1 < capacity) {
        target[index] = source[index];
        ++index;
    }
    target[index] = 0;
}

}

void SendRuntimeInit(SendRuntime* runtime) {
    LocatorInit(&runtime->locator);
    runtime->pathCount = 0;
    runtime->locatorReady = false;
    runtime->lastError = 0;
    runtime->moduleBase = nullptr;
    runtime->moduleSize = 0;

    for (size_t index = 0; index < kMaxSendPaths; ++index) {
        runtime->paths[index].name[0] = 0;
        runtime->paths[index].reference = nullptr;
        runtime->paths[index].target = nullptr;
        runtime->paths[index].functionStart = nullptr;
        runtime->paths[index].stringAddress = nullptr;
        runtime->paths[index].prologue = 0;
        runtime->paths[index].referenceCount = 0;
        runtime->paths[index].resolved = false;
        runtime->paths[index].functionFound = false;
        runtime->paths[index].lastError = 0;
    }
}

bool SendRuntimePrepare(SendRuntime* runtime) {
    if (runtime->locatorReady) {
        return true;
    }

    LocatorInit(&runtime->locator);

    void* nodeBase = nullptr;
    size_t nodeSize = LocatorSnapshotModuleSize("wrapper.node", &nodeBase);

    if (nodeBase == nullptr || nodeSize == 0) {
        nodeBase = LocatorFindModuleBase("wrapper.node");
        if (nodeBase == nullptr) {
            runtime->lastError = 126;
            return false;
        }
        nodeSize = LocatorReadModuleSize("wrapper.node", nodeBase);
    }

    if (nodeSize == 0 || nodeSize > kMaxScannableBytes) {
        runtime->lastError = 13;
        return false;
    }

    runtime->moduleBase = nodeBase;
    runtime->moduleSize = nodeSize;

    if (!LocatorAddModuleSections(&runtime->locator, nodeBase, nodeSize)) {
        runtime->lastError = 11;
        return false;
    }

    if (runtime->locator.regionCount == 0) {
        runtime->lastError = 126;
        return false;
    }

    runtime->locatorReady = true;
    return true;
}

void FillFunctionInfo(SendRuntime* runtime, SendPath* path) {
    if (path->reference == nullptr) {
        return;
    }

    int displacement = 0;
    for (size_t index = 0; index < 4; ++index) {
        displacement |= static_cast<int>(path->reference[3 + index]) << (index * 8);
    }

    path->target = path->reference + 7 + displacement;
    path->resolved = true;

    const unsigned char* start = LocatorFindFunctionStart(
        runtime->moduleBase, runtime->moduleSize, path->reference);

    if (start != nullptr) {
        path->functionStart = start;
        path->functionFound = true;

        unsigned long long prologue = 0;
        for (size_t index = 0; index < 8; ++index) {
            prologue |= static_cast<unsigned long long>(start[index]) << (index * 8);
        }
        path->prologue = prologue;
    }
}

bool SendRuntimeScanAll(SendRuntime* runtime) {
    if (runtime->pathCount != 0) {
        return true;
    }

    if (!SendRuntimePrepare(runtime)) {
        return false;
    }

    const unsigned char* stringAddresses[kKnownFunctionCount * kMaxStringHits];
    size_t ownerIndex[kKnownFunctionCount * kMaxStringHits];
    size_t stringTotal = 0;

    for (size_t index = 0; index < kKnownFunctionCount; ++index) {
        const char* name = kKnownFunctions[index];
        size_t length = TextLength(name);

        const unsigned char* hits[kMaxStringHits];
        size_t count = LocatorFindString(&runtime->locator, name, length, hits, kMaxStringHits);

        for (size_t hit = 0; hit < count; ++hit) {
            if (stringTotal >= kKnownFunctionCount * kMaxStringHits) {
                break;
            }
            stringAddresses[stringTotal] = hits[hit];
            ownerIndex[stringTotal] = index;
            ++stringTotal;
        }
    }

    const unsigned char* references[kMaxReferenceHits];
    size_t refIndices[kMaxReferenceHits];
    size_t refCount = 0;

    if (stringTotal != 0) {
        refCount = LocatorFindAllReferences(&runtime->locator, stringAddresses, stringTotal,
                                            references, refIndices, kMaxReferenceHits);
    }

    runtime->pathCount = kKnownFunctionCount;

    for (size_t index = 0; index < kKnownFunctionCount; ++index) {
        SendPath* path = &runtime->paths[index];
        path->name[0] = 0;
        CopyText(path->name, kKnownFunctions[index], sizeof(path->name));
        path->reference = nullptr;
        path->target = nullptr;
        path->functionStart = nullptr;
        path->stringAddress = nullptr;
        path->prologue = 0;
        path->referenceCount = 0;
        path->resolved = false;
        path->functionFound = false;
        path->lastError = 2;

        for (size_t hit = 0; hit < stringTotal; ++hit) {
            if (ownerIndex[hit] != index) {
                continue;
            }
            if (path->stringAddress == nullptr) {
                path->stringAddress = stringAddresses[hit];
            }
            ++path->referenceCount;
        }
    }

    for (size_t item = 0; item < refCount; ++item) {
        size_t stringSlot = refIndices[item];

        if (stringSlot >= stringTotal) {
            continue;
        }

        size_t functionIndex = ownerIndex[stringSlot];
        if (functionIndex >= kKnownFunctionCount) {
            continue;
        }

        SendPath* path = &runtime->paths[functionIndex];

        if (path->reference != nullptr) {
            continue;
        }

        path->reference = references[item];
        FillFunctionInfo(runtime, path);
        path->lastError = 0;
    }

    return true;
}

bool SendRuntimeScanAllGuarded(SendRuntime* runtime) {
    return SendRuntimeScanAll(runtime);
}

bool SendResolvePath(SendRuntime* runtime, const char* functionName, SendPath* outPath) {
    if (functionName == nullptr || outPath == nullptr) {
        runtime->lastError = 87;
        return false;
    }
    if (!SendRuntimeScanAllGuarded(runtime)) {
        outPath->name[0] = 0;
        CopyText(outPath->name, functionName, sizeof(outPath->name));
        outPath->reference = nullptr;
        outPath->target = nullptr;
        outPath->functionStart = nullptr;
        outPath->stringAddress = nullptr;
        outPath->prologue = 0;
        outPath->referenceCount = 0;
        outPath->resolved = false;
        outPath->functionFound = false;
        outPath->lastError = runtime->lastError;
        return false;
    }
    for (size_t index = 0; index < runtime->pathCount; ++index) {
        const char* stored = runtime->paths[index].name;
        const char* wanted = functionName;
        bool same = true;

        while (stored[0] != 0 || wanted[0] != 0) {
            if (stored[0] != wanted[0]) {
                same = false;
                break;
            }
            ++stored;
            ++wanted;
        }

        if (same) {
            *outPath = runtime->paths[index];
            return outPath->resolved;
        }
    }

    outPath->name[0] = 0;
    CopyText(outPath->name, functionName, sizeof(outPath->name));
    outPath->reference = nullptr;
    outPath->target = nullptr;
    outPath->functionStart = nullptr;
    outPath->stringAddress = nullptr;
    outPath->prologue = 0;
    outPath->referenceCount = 0;
    outPath->resolved = false;
    outPath->functionFound = false;
    outPath->lastError = 2;
    runtime->lastError = 2;

    return false;
}

bool SendInvoke(SendRuntime* runtime, const char* functionName, void* argument,
                unsigned long long* outResult) {
    if (functionName == nullptr) {
        runtime->lastError = 87;
        return false;
    }

    SendPath local;
    SendPath* path = nullptr;

    for (size_t index = 0; index < runtime->pathCount; ++index) {
        size_t nameIndex = 0;
        bool same = true;
        while (functionName[nameIndex] != 0 || runtime->paths[index].name[nameIndex] != 0) {
            if (functionName[nameIndex] != runtime->paths[index].name[nameIndex]) {
                same = false;
                break;
            }
            ++nameIndex;
        }
        if (same) {
            path = &runtime->paths[index];
            break;
        }
    }

    if (path == nullptr) {
        if (!SendResolvePath(runtime, functionName, &local)) {
            return false;
        }

        if (runtime->pathCount < kMaxSendPaths) {
            path = &runtime->paths[runtime->pathCount];
            *path = local;
            ++runtime->pathCount;
        } else {
            path = &local;
        }
    }

    if (path->target == nullptr) {
        runtime->lastError = 2;
        return false;
    }

    typedef unsigned long long(__fastcall * InvokeSignature)(void*);
    InvokeSignature invoke = reinterpret_cast<InvokeSignature>(
        const_cast<unsigned char*>(path->target));
    __try {
        unsigned long long result = invoke(argument);
        if (outResult != nullptr) {
            *outResult = result;
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        runtime->lastError = GetExceptionCode();
        return false;
    }
}

bool SendInvokeSend(SendRuntime* runtime, unsigned long long session, unsigned long long request,
                    unsigned long long data, unsigned char flag,
                    unsigned long long* outResult) {
    if (session == 0) {
        runtime->lastError = 6;
        return false;
    }

    const SendPath* path = nullptr;
    for (size_t index = 0; index < runtime->pathCount; ++index) {
        if (runtime->paths[index].functionStart != nullptr) {
            const char* stored = runtime->paths[index].name;
            const char* wanted = "SendSSORequestInternal";
            bool same = true;
            while (stored[0] != 0 || wanted[0] != 0) {
                if (stored[0] != wanted[0]) {
                    same = false;
                    break;
                }
                ++stored;
                ++wanted;
            }
            if (same) {
                path = &runtime->paths[index];
                break;
            }
        }
    }

    if (path == nullptr) {
        runtime->lastError = 2;
        return false;
    }

    typedef unsigned long long(__fastcall * SendSignature)(
        unsigned long long, unsigned long long, unsigned long long, unsigned char);

    SendSignature send = reinterpret_cast<SendSignature>(
        const_cast<unsigned char*>(path->functionStart));

    __try {
        unsigned long long result = send(session, request, data, flag);
        if (outResult != nullptr) {
            *outResult = result;
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        runtime->lastError = GetExceptionCode();
        return false;
    }
}

size_t SendRuntimePathCount(const SendRuntime* runtime) {
    return runtime->pathCount;
}

}