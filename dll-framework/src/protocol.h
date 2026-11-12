#pragma once

#include <windows.h>
#include <cstdint>

namespace nexuslab {

constexpr uint32_t kPipeMagic = 0x31504851u;
constexpr uint16_t kPipeVersion = 1;
constexpr size_t kHeaderSize = 40;
constexpr uint32_t kMaxCmd = 4096;
constexpr uint32_t kMaxMsg = 65536;
constexpr uint32_t kMaxBody = 16777216;
constexpr DWORD kPipeBufferSize = 65536;
constexpr size_t kMaxFrameBytes = kHeaderSize + kMaxCmd + kMaxMsg + kMaxBody;

enum PipeOp : uint16_t {
    kOpHello = 1,
    kOpSendRequest = 2,
    kOpSendAck = 3,
    kOpSendReply = 4,
    kOpError = 5,
    kOpRecvPacket = 6,
    kOpLoginState = 7,
    kOpLoginIdentityHint = 17,
    kOpClientMessageReceipt = 21,
    kOpClientMessageState = 22,
    kOpResidentState = 23,
    kOpResidentBind = 24,
    kOpSendLocate = 25,
    kOpHookInstall = 26,
    kOpHookState = 27,
    kOpSendInvoke = 28,
    kOpRecvTest = 29,
    kOpSendDryRun = 30,
    kOpCaptureTest = 31,
    kOpReadMemory = 32,
    kOpInjectRecvCapture = 33,
    kOpInjectLoginCapture = 34,
    kOpResetLoginState = 35,
    kOpInjectSendCapture = 36,
    kOpResetSendCapture = 37,
};

constexpr uint32_t kFlagWantReply = 1u << 0;
constexpr uint32_t kFlagLoggedIn = 1u << 2;

constexpr int32_t kStatusOk = 0;
constexpr int32_t kStatusConnectionChanged = -1;
constexpr int32_t kStatusInvalidRequest = -2;
constexpr int32_t kStatusConnectionChanged2 = -4;
constexpr int32_t kStatusNotReady = -7;

constexpr const char* kMsgConnectionChanged =
    "The QQ connection changed. Please restart QQ and try again.";
constexpr const char* kMsgInvalidRequest =
    "This request is not valid. Please check it and try again.";
constexpr const char* kMsgNotReady =
    "QQ is not ready. Please finish signing in and try again.";
constexpr const char* kMsgUnsupportedOp = "unsupported pipe op";

struct FrameHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t op;
    uint32_t requestId;
    int32_t status;
    uint32_t flags;
    uint32_t cmdLen;
    uint32_t msgLen;
    uint32_t bodyLen;
    uint64_t value0;
};

void WriteU16(uint8_t* p, uint16_t v);
void WriteU32(uint8_t* p, uint32_t v);
void WriteU64(uint8_t* p, uint64_t v);
uint16_t ReadU16(const uint8_t* p);
uint32_t ReadU32(const uint8_t* p);
uint64_t ReadU64(const uint8_t* p);

size_t EncodeHeader(const FrameHeader& header, uint8_t* out);
bool DecodeHeader(const uint8_t* data, size_t size, FrameHeader* header);
bool FrameLimitsOk(const FrameHeader& header);

size_t BuildPipeName(char* buffer, size_t capacity, DWORD pid, const char* suffix);

}