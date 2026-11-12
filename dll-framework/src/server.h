#pragma once

#include "protocol.h"

namespace nexuslab {

constexpr size_t kPipeNameCapacity = 256;
constexpr size_t kMaxQueueItems = 64;
constexpr DWORD kQueueWaitMs = 200;

struct OutItem {
    uint8_t data[kHeaderSize + 1024];
    size_t length;
};

struct ServerContext {
    char controlName[kPipeNameCapacity];
    char recvName[kPipeNameCapacity];

    HANDLE controlPipe;
    HANDLE recvPipe;

    HANDLE stopEvent;
    HANDLE workEvent;

    volatile LONG loggedIn;
    volatile LONG controlReady;

    unsigned long long uin;
    char uinText[32];
    volatile LONG residentState;
    volatile LONG residentError;
    unsigned long long residentActive;

    int (*bindDispatch)(void* context, unsigned int kind, unsigned int* outKind,
                        unsigned long long* outValue);
    void* residentContext;

    int (*locateFunction)(void* context, const char* name, char* outText, size_t textSize,
                          unsigned long long* outTarget, unsigned long* outError);
    void* locateContext;

    int (*hookInstall)(void* context, const char* name);
    int (*hookState)(void* context, char* outText, size_t textSize,
                     unsigned long long* outTarget, unsigned long long* outCount);
    void* hookContext;
    int (*sendInvoke)(void* context, char* outText, size_t textSize,
                      unsigned long long* outResult);
    void* invokeContext;
    int (*sendDryRun)(void* context, char* outText, size_t textSize,
                      unsigned long long* outResult);
    int (*captureTest)(void* context, char* outText, size_t textSize,
                       unsigned long long* outResult);
    int (*readMemory)(void* context, unsigned long long address, uint8_t* buffer,
                      uint32_t capacity, uint32_t* outLength);
    int (*injectRecvCapture)(void* context, char* outText, size_t textSize,
                             unsigned long long* outResult);
    int (*injectLoginCapture)(void* context, char* outText, size_t textSize,
                              unsigned long long* outResult);
    int (*resetLoginState)(void* context, char* outText, size_t textSize,
                           unsigned long long* outResult);
    int (*injectSendCapture)(void* context, char* outText, size_t textSize,
                             unsigned long long* outResult);
    int (*resetSendCapture)(void* context, char* outText, size_t textSize,
                            unsigned long long* outResult);
    int (*sendAck)(void* context, const uint8_t* cmd, uint32_t cmdLength,
                   const uint8_t* body, uint32_t bodyLength);
    int (*sendReply)(void* context, int* outError, uint8_t* body, uint32_t bodyCapacity,
                     uint32_t* outBodyLength);

    char sendQueue[kMaxQueueItems][kHeaderSize + 512];
    size_t sendQueueLength[kMaxQueueItems];
    size_t sendQueueHead;
    size_t sendQueueCount;
    CRITICAL_SECTION queueLock;
    bool queueLockReady;
    uint8_t cmdPayload[256];
    uint32_t cmdPayloadLength;
    uint8_t bodyPayload[512];
    uint32_t bodyPayloadLength;
    volatile LONG recvSeq;
    DWORD pid;
};
bool StartServers(ServerContext* ctx);
void StopServers(ServerContext* ctx);
bool EnqueueRecvPacket(ServerContext* ctx, int32_t error, const char* cmd, const char* uin,
                       const uint8_t* body, size_t bodyLength);
bool EnqueueLoginState(ServerContext* ctx, bool loggedIn, unsigned long long uin);

DWORD WINAPI ControlThread(LPVOID parameter);
DWORD WINAPI RecvThread(LPVOID parameter);
DWORD WINAPI WriterThread(LPVOID parameter);

void SetLoggedIn(ServerContext* ctx, bool value);

void SetLoginState(ServerContext* ctx, bool value, unsigned long long uin);

}