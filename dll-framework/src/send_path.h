#pragma once

#include "locator.h"

namespace nexuslab {

constexpr size_t kMaxFuncNameLength = 96;
constexpr size_t kMaxSendPaths = 8;

struct SendPath {
    char name[kMaxFuncNameLength];
    const unsigned char* reference;
    const unsigned char* target;
    const unsigned char* functionStart;
    const unsigned char* stringAddress;
    unsigned long long prologue;
    unsigned long referenceCount;
    bool resolved;
    bool functionFound;
    unsigned long lastError;
};

struct SendRuntime {
    LocatorContext locator;
    SendPath paths[kMaxSendPaths];
    size_t pathCount;
    bool locatorReady;
    unsigned long lastError;
    void* moduleBase;
    size_t moduleSize;
    volatile long scanState;
    volatile long scanError;
};

void SendRuntimeInit(SendRuntime* runtime);

bool SendRuntimePrepare(SendRuntime* runtime);

bool SendResolvePath(SendRuntime* runtime, const char* functionName, SendPath* outPath);

bool SendInvoke(SendRuntime* runtime, const char* functionName, void* argument,
                unsigned long long* outResult);
bool SendInvokeSend(SendRuntime* runtime, unsigned long long session, unsigned long long request,
                    unsigned long long data, unsigned char flag,
                    unsigned long long* outResult);

size_t SendRuntimePathCount(const SendRuntime* runtime);

}