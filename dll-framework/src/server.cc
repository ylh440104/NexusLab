#include "server.h"

namespace nexuslab {

namespace {

constexpr DWORD kNoDataSleepMs = 10;
constexpr DWORD kListenSleepMs = 10;
constexpr DWORD kRetrySleepMs = 50;
constexpr DWORD kPreConnectDelayMs = 250;
constexpr DWORD kWriteStallMs = 60000;

HANDLE CreatePipeInstance(const char* name) {
    HANDLE pipe = CreateNamedPipeA(
        name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        255,
        0x200000,
        0x200000,
        0,
        nullptr);

    if (pipe != INVALID_HANDLE_VALUE) {
        return pipe;
    }

    pipe = CreateNamedPipeA(
        name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        255,
        0x80000,
        0x80000,
        0,
        nullptr);

    if (pipe != INVALID_HANDLE_VALUE) {
        return pipe;
    }

    return CreateNamedPipeA(
        name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        255,
        0x10000,
        0x10000,
        0,
        nullptr);
}

bool Stopped(HANDLE stopEvent) {
    return WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0;
}

bool WaitForConnection(HANDLE pipe, HANDLE stopEvent) {
    while (true) {
        if (Stopped(stopEvent)) {
            return false;
        }
        BOOL connected = ConnectNamedPipe(pipe, nullptr);
        if (connected) {
            return true;
        }
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) {
            return true;
        }
        if (err == ERROR_PIPE_LISTENING) {
            Sleep(kListenSleepMs);
            continue;
        }
        if (err == ERROR_NO_DATA) {
            Sleep(kNoDataSleepMs);
            continue;
        }
        if (err == ERROR_INVALID_HANDLE) {
            return false;
        }
        Sleep(kRetrySleepMs);
        return false;
    }
}

bool ReadExact(HANDLE pipe, HANDLE stopEvent, void* buffer, size_t length) {
    uint8_t* cursor = static_cast<uint8_t*>(buffer);
    size_t remaining = length;
    DWORD idleSince = GetTickCount();

    while (remaining != 0) {
        if (Stopped(stopEvent)) {
            return false;
        }

        DWORD chunk = static_cast<DWORD>(remaining < 0x10000 ? remaining : 0x10000);
        DWORD read = 0;
        BOOL ok = ReadFile(pipe, cursor, chunk, &read, nullptr);

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA) {
                if (GetTickCount() - idleSince > kWriteStallMs) {
                    return false;
                }
                Sleep(kNoDataSleepMs);
                continue;
            }
            return false;
        }
        if (read == 0) {
            if (GetTickCount() - idleSince > kWriteStallMs) {
                return false;
            }
            Sleep(kNoDataSleepMs);
            continue;
        }
        idleSince = GetTickCount();
        cursor += read;
        remaining -= read;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* buffer, size_t length) {
    const uint8_t* cursor = static_cast<const uint8_t*>(buffer);
    size_t remaining = length;
    DWORD startedAt = GetTickCount();
    while (remaining != 0) {
        DWORD chunk = static_cast<DWORD>(remaining < 0x10000 ? remaining : 0x10000);
        DWORD written = 0;
        BOOL ok = WriteFile(pipe, cursor, chunk, &written, nullptr);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA) {
                if (GetTickCount() - startedAt > kWriteStallMs) {
                    return false;
                }
                Sleep(kNoDataSleepMs);
                continue;
            }
            return false;
        }
        if (written == 0) {
            if (GetTickCount() - startedAt > kWriteStallMs) {
                return false;
            }
            Sleep(kNoDataSleepMs);
            continue;
        }
        cursor += written;
        remaining -= written;
        startedAt = GetTickCount();
    }
    return true;
}

size_t StringLength(const char* text) {
    size_t count = 0;
    while (text[count] != 0) {
        ++count;
    }
    return count;
}

bool ReadPayloadTo(HANDLE pipe, HANDLE stopEvent, uint32_t length, uint8_t* target,
                   uint32_t capacity) {
    if (length == 0) {
        return true;
    }

    size_t offset = 0;
    uint8_t scratch[256];
    size_t remaining = length;

    while (remaining != 0) {
        size_t chunk = remaining < sizeof(scratch) ? remaining : sizeof(scratch);
        if (!ReadExact(pipe, stopEvent, scratch, chunk)) {
            return false;
        }

        if (target != nullptr && offset < capacity) {
            size_t room = capacity - offset;
            size_t copy = chunk < room ? chunk : room;
            for (size_t i = 0; i < copy; ++i) {
                target[offset + i] = scratch[i];
            }
        }

        offset += chunk;
        remaining -= chunk;
    }

    return true;
}

bool ReadPayload(HANDLE pipe, HANDLE stopEvent, uint32_t length) {
    return ReadPayloadTo(pipe, stopEvent, length, nullptr, 0);
}

bool SendReply(HANDLE pipe, uint16_t op, uint32_t requestId, uint32_t flags,
               int32_t status, const char* message) {
    uint8_t buffer[kHeaderSize + 128];

    FrameHeader reply;
    reply.magic = kPipeMagic;
    reply.version = kPipeVersion;
    reply.op = op;
    reply.requestId = requestId;
    reply.status = status;
    reply.flags = flags;
    reply.cmdLen = 0;
    reply.msgLen = 0;
    reply.bodyLen = 0;
    reply.value0 = 0;

    size_t size = EncodeHeader(reply, buffer);

    if (message != nullptr && status != kStatusOk) {
        size_t length = StringLength(message);
        if (length > 127) {
            length = 127;
        }
        WriteU32(buffer + 24, static_cast<uint32_t>(length));
        for (size_t i = 0; i < length; ++i) {
            buffer[size + i] = static_cast<uint8_t>(message[i]);
        }
        size += length;
    }

    return WriteExact(pipe, buffer, size);
}

bool SendHello(ServerContext* ctx, HANDLE pipe, const char* pipeName, unsigned long pid) {
    uint8_t buffer[kHeaderSize + kPipeNameCapacity];

    size_t nameLength = StringLength(pipeName);
    if (nameLength > kPipeNameCapacity - 1) {
        nameLength = kPipeNameCapacity - 1;
    }

    FrameHeader frame;
    frame.magic = kPipeMagic;
    frame.version = kPipeVersion;
    frame.op = kOpHello;
    frame.requestId = 0;
    frame.status = 0;
    frame.flags = static_cast<uint32_t>(ctx->loggedIn != 0 ? kFlagLoggedIn : 0);
    frame.cmdLen = 0;
    frame.msgLen = static_cast<uint32_t>(nameLength);
    frame.bodyLen = 0;
    frame.value0 = pid;

    size_t size = EncodeHeader(frame, buffer);

    for (size_t i = 0; i < nameLength; ++i) {
        buffer[size + i] = static_cast<uint8_t>(pipeName[i]);
    }
    size += nameLength;

    return WriteExact(pipe, buffer, size);
}

void MarkBroken(HANDLE pipe) {
    if (pipe != INVALID_HANDLE_VALUE && pipe != nullptr) {
        CancelIoEx(pipe, nullptr);
        DisconnectNamedPipe(pipe);
    }
}

bool HandleControlFrame(ServerContext* ctx, HANDLE pipe, const FrameHeader& request) {
    if (request.op == kOpHello) {
        return SendHello(ctx, pipe, ctx->controlName, ctx->pid);
    }

    if (request.op == kOpLoginState) {
        uint8_t buffer[kHeaderSize + 32];

        bool loggedIn = ctx->loggedIn != 0;
        size_t textLength = 0;
        while (ctx->uinText[textLength] != 0 && textLength < sizeof(ctx->uinText)) {
            ++textLength;
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpLoginState;
        reply.requestId = request.requestId;
        reply.status = loggedIn ? 1 : 0;
        reply.flags = static_cast<uint32_t>(loggedIn ? kFlagLoggedIn : 0);
        reply.cmdLen = 0;
        reply.msgLen = static_cast<uint32_t>(loggedIn ? textLength : 0);
        reply.bodyLen = 0;
        reply.value0 = loggedIn ? ctx->uin : 0;

        size_t size = EncodeHeader(reply, buffer);

        if (loggedIn) {
            for (size_t i = 0; i < textLength; ++i) {
                buffer[size + i] = static_cast<uint8_t>(ctx->uinText[i]);
            }
            size += textLength;
        }

        return WriteExact(pipe, buffer, size);
    }

    if (request.op == kOpResidentState) {
        uint8_t buffer[kHeaderSize];
        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpResidentState;
        reply.requestId = request.requestId;
        reply.status = static_cast<int32_t>(ctx->residentError);
        reply.flags = static_cast<uint32_t>(ctx->residentState);
        reply.cmdLen = 0;
        reply.msgLen = 0;
        reply.bodyLen = 0;
        reply.value0 = ctx->residentActive;
        EncodeHeader(reply, buffer);
        return WriteExact(pipe, buffer, kHeaderSize);
    }

    if (request.op == kOpResidentBind) {
        uint32_t category = request.flags;
        uint32_t kind = request.status;

        unsigned int resolvedKind = kind;
        unsigned long long boundValue = 0;
        int bound = 0;

        if (ctx->bindDispatch != nullptr) {
            bound = ctx->bindDispatch(ctx->residentContext, kind, &resolvedKind, &boundValue);
        }

        uint8_t buffer[kHeaderSize];
        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpResidentBind;
        reply.requestId = request.requestId;
        reply.status = bound;
        reply.flags = resolvedKind;
        reply.cmdLen = 0;
        reply.msgLen = 0;
        reply.bodyLen = 0;
        reply.value0 = boundValue + static_cast<uint64_t>(category * 0);
        EncodeHeader(reply, buffer);
        return WriteExact(pipe, buffer, kHeaderSize);
    }

    if (request.op == kOpSendLocate) {
        uint8_t nameBuffer[96];
        size_t nameLength = ctx->cmdPayloadLength;
        if (nameLength > sizeof(nameBuffer) - 1) {
            nameLength = sizeof(nameBuffer) - 1;
        }

        for (size_t i = 0; i < nameLength; ++i) {
            nameBuffer[i] = ctx->cmdPayload[i];
        }
        nameBuffer[nameLength] = 0;

        char detail[256];
        detail[0] = 0;

        unsigned long long target = 0;
        unsigned long locateError = 0;
        int located = 0;

        if (ctx->locateFunction != nullptr && nameLength != 0) {
            char narrow[96];
            for (size_t i = 0; i < nameLength; ++i) {
                narrow[i] = static_cast<char>(nameBuffer[i]);
            }
            narrow[nameLength] = 0;
            located = ctx->locateFunction(ctx->locateContext, narrow, detail,
                                          sizeof(detail), &target, &locateError);
        }

        size_t detailLength = 0;
        while (detail[detailLength] != 0) {
            ++detailLength;
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpSendLocate;
        reply.requestId = request.requestId;
        reply.status = located;
        reply.flags = static_cast<uint32_t>(locateError);
        reply.cmdLen = 0;
        reply.msgLen = static_cast<uint32_t>(detailLength);
        reply.bodyLen = 0;
        reply.value0 = target;

        uint8_t header[kHeaderSize];
        EncodeHeader(reply, header);

        if (!WriteExact(pipe, header, kHeaderSize)) {
            return false;
        }

        if (detailLength != 0) {
            if (!WriteExact(pipe, reinterpret_cast<const uint8_t*>(detail), detailLength)) {
                return false;
            }
        }
        return true;
    }

    if (request.op == kOpHookInstall) {
        char nameBuffer[96];
        size_t nameLength = ctx->cmdPayloadLength;
        if (nameLength > sizeof(nameBuffer) - 1) {
            nameLength = sizeof(nameBuffer) - 1;
        }

        for (size_t i = 0; i < nameLength; ++i) {
            nameBuffer[i] = static_cast<char>(ctx->cmdPayload[i]);
        }
        nameBuffer[nameLength] = 0;

        int installed = 0;
        if (ctx->hookInstall != nullptr && nameLength != 0) {
            installed = ctx->hookInstall(ctx->hookContext, nameBuffer);
        }

        return SendReply(pipe, request.op, request.requestId, 0,
                         installed == 1 ? kStatusOk : kStatusInvalidRequest,
                         installed == 1 ? nullptr : "hook install failed");
    }

    if (request.op == kOpHookState) {
        char detail[256];
        detail[0] = 0;

        unsigned long long target = 0;
        unsigned long long count = 0;
        int state = 0;

        if (ctx->hookState != nullptr) {
            state = ctx->hookState(ctx->hookContext, detail, sizeof(detail), &target, &count);
        }

        size_t detailLength = 0;
        while (detail[detailLength] != 0) {
            ++detailLength;
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpHookState;
        reply.requestId = request.requestId;
        reply.status = state;
        reply.flags = 0;
        reply.cmdLen = 0;
        reply.msgLen = static_cast<uint32_t>(detailLength);
        reply.bodyLen = 0;
        reply.value0 = target;

        uint8_t header[kHeaderSize];
        EncodeHeader(reply, header);

        if (!WriteExact(pipe, header, kHeaderSize)) {
            return false;
        }

        if (detailLength != 0) {
            if (!WriteExact(pipe, reinterpret_cast<const uint8_t*>(detail), detailLength)) {
                return false;
            }
        }

        return true;
    }

    if (request.op == kOpSendInvoke) {
        char detail[256];
        detail[0] = 0;

        unsigned long long result = 0;
        int invoked = 0;

        if (ctx->sendInvoke != nullptr) {
            invoked = ctx->sendInvoke(ctx->invokeContext, detail, sizeof(detail), &result);
        }

        size_t detailLength = 0;
        while (detail[detailLength] != 0) {
            ++detailLength;
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpSendInvoke;
        reply.requestId = request.requestId;
        reply.status = invoked;
        reply.flags = 0;
        reply.cmdLen = 0;
        reply.msgLen = static_cast<uint32_t>(detailLength);
        reply.bodyLen = 0;
        reply.value0 = result;

        uint8_t header[kHeaderSize];
        EncodeHeader(reply, header);

        if (!WriteExact(pipe, header, kHeaderSize)) {
            return false;
        }

        if (detailLength != 0) {
            if (!WriteExact(pipe, reinterpret_cast<const uint8_t*>(detail), detailLength)) {
                return false;
            }
        }

        return true;
    }

    if (request.op == kOpRecvTest) {
        const char* cmd = "MessageSvc.PbSendMsg";
        const char* uin = "10001";
        const uint8_t body[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

        bool queued = EnqueueRecvPacket(ctx, 0, cmd, uin, body, sizeof(body));

        return SendReply(pipe, request.op, request.requestId, 0,
                         queued ? kStatusOk : kStatusInvalidRequest,
                         queued ? nullptr : "queue failed");
    }

    if (request.op == kOpSendDryRun) {
        char detail[256];
        detail[0] = 0;

        unsigned long long result = 0;
        int ready = 0;

        if (ctx->sendDryRun != nullptr) {
            ready = ctx->sendDryRun(ctx->invokeContext, detail, sizeof(detail), &result);
        }

        size_t detailLength = 0;
        while (detail[detailLength] != 0) {
            ++detailLength;
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpSendDryRun;
        reply.requestId = request.requestId;
        reply.status = ready;
        reply.flags = 0;
        reply.cmdLen = 0;
        reply.msgLen = static_cast<uint32_t>(detailLength);
        reply.bodyLen = 0;
        reply.value0 = result;

        uint8_t header[kHeaderSize];
        EncodeHeader(reply, header);

        if (!WriteExact(pipe, header, kHeaderSize)) {
            return false;
        }

        if (detailLength != 0) {
            if (!WriteExact(pipe, reinterpret_cast<const uint8_t*>(detail), detailLength)) {
                return false;
            }
        }

        return true;
    }

    if (request.op == kOpCaptureTest) {
        char detail[256];
        detail[0] = 0;

        unsigned long long result = 0;
        int tested = 0;

        if (ctx->captureTest != nullptr) {
            tested = ctx->captureTest(ctx->invokeContext, detail, sizeof(detail), &result);
        }

        size_t detailLength = 0;
        while (detail[detailLength] != 0) {
            ++detailLength;
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpCaptureTest;
        reply.requestId = request.requestId;
        reply.status = tested;
        reply.flags = 0;
        reply.cmdLen = 0;
        reply.msgLen = static_cast<uint32_t>(detailLength);
        reply.bodyLen = 0;
        reply.value0 = result;

        uint8_t header[kHeaderSize];
        EncodeHeader(reply, header);

        if (!WriteExact(pipe, header, kHeaderSize)) {
            return false;
        }

        if (detailLength != 0) {
            if (!WriteExact(pipe, reinterpret_cast<const uint8_t*>(detail), detailLength)) {
                return false;
            }
        }

        return true;
    }

    if (request.op == kOpReadMemory) {
        if (ctx->cmdPayloadLength < 8) {
            return SendReply(pipe, request.op, request.requestId, 0,
                             kStatusInvalidRequest, kMsgInvalidRequest);
        }

        unsigned long long address = 0;
        for (size_t i = 0; i < 8; ++i) {
            address |= static_cast<unsigned long long>(ctx->cmdPayload[i]) << (i * 8);
        }

        uint32_t readLength = 128;
        if (ctx->bodyPayloadLength >= 4) {
            readLength = 0;
            for (size_t i = 0; i < 4; ++i) {
                readLength |= static_cast<uint32_t>(ctx->bodyPayload[i]) << (i * 8);
            }
        }
        if (readLength == 0 || readLength > 512) {
            readLength = 128;
        }

        uint8_t buffer[512];
        uint32_t actualLength = 0;
        int readOk = 0;

        if (ctx->readMemory != nullptr) {
            readOk = ctx->readMemory(ctx->invokeContext, address, buffer, readLength,
                                     &actualLength);
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = kOpReadMemory;
        reply.requestId = request.requestId;
        reply.status = readOk;
        reply.flags = 0;
        reply.cmdLen = 0;
        reply.msgLen = 0;
        reply.bodyLen = readOk == 1 ? actualLength : 0;
        reply.value0 = address;

        uint8_t header[kHeaderSize];
        EncodeHeader(reply, header);

        if (!WriteExact(pipe, header, kHeaderSize)) {
            return false;
        }

        if (readOk == 1 && actualLength != 0) {
            if (!WriteExact(pipe, buffer, actualLength)) {
                return false;
            }
        }
        return true;
    }

if (request.op == kOpInjectRecvCapture || request.op == kOpInjectLoginCapture ||
        request.op == kOpResetLoginState || request.op == kOpInjectSendCapture ||
        request.op == kOpResetSendCapture) {
        char detail[256];
        detail[0] = 0;
        unsigned long long result = 0;
        int tested = 0;

        if (request.op == kOpInjectRecvCapture && ctx->injectRecvCapture != nullptr) {
            tested = ctx->injectRecvCapture(ctx->invokeContext, detail, sizeof(detail),
                                            &result);
        }
        if (request.op == kOpInjectLoginCapture && ctx->injectLoginCapture != nullptr) {
            tested = ctx->injectLoginCapture(ctx->invokeContext, detail, sizeof(detail),
                                             &result);
        }
        if (request.op == kOpResetLoginState && ctx->resetLoginState != nullptr) {
            tested = ctx->resetLoginState(ctx->invokeContext, detail, sizeof(detail),
                                          &result);
        }
        if (request.op == kOpInjectSendCapture && ctx->injectSendCapture != nullptr) {
            tested = ctx->injectSendCapture(ctx->invokeContext, detail, sizeof(detail),
                                            &result);
        }
        if (request.op == kOpResetSendCapture && ctx->resetSendCapture != nullptr) {
            tested = ctx->resetSendCapture(ctx->invokeContext, detail, sizeof(detail),
                                           &result);
        }

        size_t detailLength = 0;
        while (detail[detailLength] != 0) {
            ++detailLength;
        }

        FrameHeader reply;
        reply.magic = kPipeMagic;
        reply.version = kPipeVersion;
        reply.op = request.op;
        reply.requestId = request.requestId;
        reply.status = tested;
        reply.flags = 0;
        reply.cmdLen = 0;
        reply.msgLen = static_cast<uint32_t>(detailLength);
        reply.bodyLen = 0;
        reply.value0 = result;

        uint8_t header[kHeaderSize];
        EncodeHeader(reply, header);

        if (!WriteExact(pipe, header, kHeaderSize)) {
            return false;
        }

        if (detailLength != 0) {
            if (!WriteExact(pipe, reinterpret_cast<const uint8_t*>(detail), detailLength)) {
                return false;
            }
        }

        return true;
    }

    if (request.op == kOpSendRequest) {
        int acked = ctx->sendAck != nullptr
            ? ctx->sendAck(ctx->invokeContext, ctx->cmdPayload, ctx->cmdPayloadLength,
                           ctx->bodyPayload, ctx->bodyPayloadLength)
            : 0;

        SendReply(pipe, kOpSendAck, request.requestId, 0,
                  acked == 1 ? kStatusOk : kStatusInvalidRequest,
                  acked == 1 ? nullptr : kMsgNotReady);

        if (acked != 1) {
            return true;
        }

        if (request.flags & kFlagWantReply) {
            uint8_t replyBody[512];
            uint32_t replyBodyLength = 0;
            int replyError = 0;

            int replied = ctx->sendReply != nullptr
                ? ctx->sendReply(ctx->invokeContext, &replyError, replyBody,
                                 static_cast<uint32_t>(sizeof(replyBody)), &replyBodyLength)
                : 0;

            FrameHeader reply;
            reply.magic = kPipeMagic;
            reply.version = kPipeVersion;
            reply.op = kOpSendReply;
            reply.requestId = request.requestId;
            reply.status = replied == 1 ? replyError : kStatusNotReady;
            reply.flags = 0;
            reply.cmdLen = 0;
            reply.msgLen = 0;
            reply.bodyLen = replied == 1 ? replyBodyLength : 0;
            reply.value0 = 0;

            uint8_t header[kHeaderSize];
            EncodeHeader(reply, header);

            if (!WriteExact(pipe, header, kHeaderSize)) {
                return false;
            }

            if (replied == 1 && replyBodyLength != 0) {
                if (!WriteExact(pipe, replyBody, replyBodyLength)) {
                    return false;
                }
            }
        }

        return true;
    }

    if (request.op == kOpSendAck || request.op == kOpSendReply || request.op == kOpRecvPacket) {
        return SendReply(pipe, request.op, request.requestId, request.flags,
                         kStatusConnectionChanged2, kMsgConnectionChanged);
    }

    if (request.op == kOpLoginIdentityHint) {
        unsigned long long hintedUin = request.value0;
        if (hintedUin >= 10000ULL && hintedUin <= 999999999999ULL) {
            SetLoginState(ctx, true, hintedUin);
            EnqueueLoginState(ctx, true, hintedUin);
        }
        return SendReply(pipe, kOpSendAck, request.requestId, 0, kStatusOk, nullptr);
    }

    if (request.op == kOpClientMessageReceipt || request.op == kOpClientMessageState) {
        return SendReply(pipe, request.op, request.requestId, request.flags,
                         kStatusConnectionChanged, kMsgConnectionChanged);
    }

    return SendReply(pipe, kOpError, request.requestId, request.flags,
                     kStatusConnectionChanged, kMsgUnsupportedOp);
}

bool Enqueue(ServerContext* ctx, const uint8_t* data, size_t length) {
    if (!ctx->queueLockReady) {
        return false;
    }
    EnterCriticalSection(&ctx->queueLock);
    if (ctx->sendQueueCount >= kMaxQueueItems) {
        LeaveCriticalSection(&ctx->queueLock);
        return false;
    }
    size_t slot = (ctx->sendQueueHead + ctx->sendQueueCount) % kMaxQueueItems;
    if (length > sizeof(ctx->sendQueue[0])) {
        LeaveCriticalSection(&ctx->queueLock);
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        ctx->sendQueue[slot][i] = data[i];
    }
    ctx->sendQueueLength[slot] = length;
    ctx->sendQueueCount++;
    LeaveCriticalSection(&ctx->queueLock);
    if (ctx->workEvent != nullptr) {
        SetEvent(ctx->workEvent);
    }
    return true;
}
}

bool EnqueueRecvPacket(ServerContext* ctx, int32_t error, const char* cmd, const char* uin,
                       const uint8_t* body, size_t bodyLength) {
    if (ctx == nullptr || cmd == nullptr || uin == nullptr) {
        return false;
    }

    if (bodyLength > 8192) {
        bodyLength = 8192;
    }

    size_t cmdLength = StringLength(cmd);
    size_t uinLength = StringLength(uin);

    FrameHeader frame;
    frame.magic = kPipeMagic;
    frame.version = kPipeVersion;
    frame.op = kOpRecvPacket;
    frame.requestId = 0;
    frame.status = error;
    frame.flags = 0;
    frame.cmdLen = static_cast<uint32_t>(cmdLength);
    frame.msgLen = static_cast<uint32_t>(uinLength);
    frame.bodyLen = static_cast<uint32_t>(bodyLength);
    frame.value0 = static_cast<unsigned long long>(
        InterlockedIncrement(&ctx->recvSeq));

    uint8_t packet[kHeaderSize + 8192 + 64 + 256];
    size_t cursor = EncodeHeader(frame, packet);

    if (cursor + cmdLength + uinLength + bodyLength > sizeof(packet)) {
        return false;
    }

    for (size_t i = 0; i < cmdLength; ++i) {
        packet[cursor + i] = static_cast<uint8_t>(cmd[i]);
    }
    cursor += cmdLength;

    for (size_t i = 0; i < uinLength; ++i) {
        packet[cursor + i] = static_cast<uint8_t>(uin[i]);
    }
    cursor += uinLength;

    for (size_t i = 0; i < bodyLength; ++i) {
        packet[cursor + i] = body[i];
    }
    cursor += bodyLength;
    return Enqueue(ctx, packet, cursor);
}
bool EnqueueLoginState(ServerContext* ctx, bool loggedIn, unsigned long long uin) {
    if (ctx == nullptr) {
        return false;
    }

    char uinText[32];
    size_t uinLength = 0;

    if (loggedIn && uin != 0) {
        char digits[32];
        size_t count = 0;
        unsigned long long remaining = uin;

        while (remaining != 0 && count < sizeof(digits)) {
            digits[count] = static_cast<char>('0' + (remaining % 10));
            remaining /= 10;
            ++count;
        }

        for (size_t i = 0; i < count; ++i) {
            uinText[i] = digits[count - 1 - i];
        }
        uinLength = count;
    }

    uinText[uinLength] = 0;

    FrameHeader frame;
    frame.magic = kPipeMagic;
    frame.version = kPipeVersion;
    frame.op = kOpLoginState;
    frame.requestId = 0;
    frame.status = loggedIn ? 1 : 0;
    frame.flags = loggedIn ? kFlagLoggedIn : 0;
    frame.cmdLen = 0;
    frame.msgLen = static_cast<uint32_t>(uinLength);
    frame.bodyLen = 0;
    frame.value0 = loggedIn ? uin : 0;

    uint8_t packet[kHeaderSize + 32];
    size_t cursor = EncodeHeader(frame, packet);

    for (size_t i = 0; i < uinLength; ++i) {
        packet[cursor + i] = static_cast<uint8_t>(uinText[i]);
    }
    cursor += uinLength;

    return Enqueue(ctx, packet, cursor);
}
bool StartServers(ServerContext* ctx) {
    ctx->pid = GetCurrentProcessId();
    ctx->controlPipe = INVALID_HANDLE_VALUE;
    ctx->recvPipe = INVALID_HANDLE_VALUE;
    ctx->controlReady = 0;
    ctx->loggedIn = 0;
    ctx->uin = 0;
    ctx->uinText[0] = 0;
    ctx->residentState = -1;
    ctx->residentError = 0;
    ctx->residentActive = 0;
    ctx->bindDispatch = nullptr;
    ctx->residentContext = nullptr;
    ctx->locateFunction = nullptr;
    ctx->locateContext = nullptr;
    ctx->hookInstall = nullptr;
    ctx->hookState = nullptr;
    ctx->hookContext = nullptr;
    ctx->sendInvoke = nullptr;
    ctx->invokeContext = nullptr;
    ctx->sendDryRun = nullptr;
    ctx->captureTest = nullptr;
    ctx->readMemory = nullptr;
    ctx->injectRecvCapture = nullptr;
    ctx->injectLoginCapture = nullptr;
    ctx->resetLoginState = nullptr;
    ctx->injectSendCapture = nullptr;
    ctx->resetSendCapture = nullptr;
    ctx->sendAck = nullptr;
    ctx->sendReply = nullptr;
    ctx->sendQueueHead = 0;
    ctx->sendQueueCount = 0;
    ctx->queueLockReady = false;

    BuildPipeName(ctx->controlName, sizeof(ctx->controlName), ctx->pid, "control");
    BuildPipeName(ctx->recvName, sizeof(ctx->recvName), ctx->pid, "recv");

    ctx->stopEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (ctx->stopEvent == nullptr) {
        return false;
    }

    ctx->workEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    if (ctx->workEvent == nullptr) {
        return false;
    }

    InitializeCriticalSection(&ctx->queueLock);
    ctx->queueLockReady = true;

    return true;
}

void StopServers(ServerContext* ctx) {
    if (ctx->stopEvent != nullptr) {
        SetEvent(ctx->stopEvent);
    }
    if (ctx->workEvent != nullptr) {
        SetEvent(ctx->workEvent);
    }

    MarkBroken(ctx->controlPipe);
    MarkBroken(ctx->recvPipe);

    if (ctx->controlPipe != INVALID_HANDLE_VALUE && ctx->controlPipe != nullptr) {
        CloseHandle(ctx->controlPipe);
        ctx->controlPipe = INVALID_HANDLE_VALUE;
    }
    if (ctx->recvPipe != INVALID_HANDLE_VALUE && ctx->recvPipe != nullptr) {
        CloseHandle(ctx->recvPipe);
        ctx->recvPipe = INVALID_HANDLE_VALUE;
    }

    if (ctx->queueLockReady) {
        DeleteCriticalSection(&ctx->queueLock);
        ctx->queueLockReady = false;
    }

    if (ctx->workEvent != nullptr) {
        CloseHandle(ctx->workEvent);
        ctx->workEvent = nullptr;
    }
    if (ctx->stopEvent != nullptr) {
        CloseHandle(ctx->stopEvent);
        ctx->stopEvent = nullptr;
    }
}

void SetLoggedIn(ServerContext* ctx, bool value) {
    SetLoginState(ctx, value, ctx->uin);
}

void SetLoginState(ServerContext* ctx, bool value, unsigned long long uin) {
    InterlockedExchange(&ctx->loggedIn, value ? 1 : 0);

    ctx->uin = value ? uin : 0;

    size_t textLength = 0;
    if (value && uin != 0) {
        char digits[32];
        size_t count = 0;
        unsigned long long remaining = uin;
        while (remaining != 0 && count < sizeof(digits)) {
            digits[count++] = static_cast<char>('0' + (remaining % 10));
            remaining /= 10;
        }
        while (count != 0 && textLength + 1 < sizeof(ctx->uinText)) {
            --count;
            ctx->uinText[textLength++] = digits[count];
        }
    }
    ctx->uinText[textLength] = 0;

    uint8_t buffer[kHeaderSize + 32];

    FrameHeader frame;
    frame.magic = kPipeMagic;
    frame.version = kPipeVersion;
    frame.op = kOpLoginState;
    frame.requestId = 0;
    frame.status = value ? 1 : 0;
    frame.flags = static_cast<uint32_t>(value ? kFlagLoggedIn : 0);
    frame.cmdLen = 0;
    frame.msgLen = static_cast<uint32_t>(textLength);
    frame.bodyLen = 0;
    frame.value0 = value ? uin : 0;

    size_t size = EncodeHeader(frame, buffer);

    for (size_t i = 0; i < textLength; ++i) {
        buffer[size + i] = static_cast<uint8_t>(ctx->uinText[i]);
    }
    size += textLength;

    Enqueue(ctx, buffer, size);
}

DWORD WINAPI ControlThread(LPVOID parameter) {
    ServerContext* ctx = static_cast<ServerContext*>(parameter);

    int attempts = 0;
    while (!Stopped(ctx->stopEvent) && attempts < 200) {
        HANDLE pipe = CreatePipeInstance(ctx->controlName);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(kRetrySleepMs);
            ++attempts;
            continue;
        }

        ctx->controlPipe = pipe;
        InterlockedExchange(&ctx->controlReady, 1);

        if (!WaitForConnection(pipe, ctx->stopEvent)) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            if (ctx->controlPipe == pipe) {
                ctx->controlPipe = INVALID_HANDLE_VALUE;
            }
            if (Stopped(ctx->stopEvent)) {
                return 0;
            }
            ++attempts;
            continue;
        }

        uint8_t headerBytes[kHeaderSize];

        SendHello(ctx, pipe, ctx->controlName, ctx->pid);

        while (!Stopped(ctx->stopEvent)) {
            if (!ReadExact(pipe, ctx->stopEvent, headerBytes, kHeaderSize)) {
                break;
            }

            FrameHeader request;
            if (!DecodeHeader(headerBytes, kHeaderSize, &request)) {
                break;
            }

            bool payloadOk = true;
            if (request.cmdLen != 0) {
                uint32_t cacheCapacity = static_cast<uint32_t>(sizeof(ctx->cmdPayload));
                payloadOk = payloadOk &&
                    ReadPayloadTo(pipe, ctx->stopEvent, request.cmdLen, ctx->cmdPayload,
                                  cacheCapacity);
                ctx->cmdPayloadLength = request.cmdLen < cacheCapacity ? request.cmdLen
                                                                       : cacheCapacity;
            } else {
                ctx->cmdPayloadLength = 0;
            }
            if (request.msgLen != 0) {
                payloadOk = payloadOk && ReadPayload(pipe, ctx->stopEvent, request.msgLen);
            }
            if (request.bodyLen != 0) {
                uint32_t bodyCapacity = static_cast<uint32_t>(sizeof(ctx->bodyPayload));
                payloadOk = payloadOk &&
                    ReadPayloadTo(pipe, ctx->stopEvent, request.bodyLen, ctx->bodyPayload,
                                  bodyCapacity);
                ctx->bodyPayloadLength = request.bodyLen < bodyCapacity ? request.bodyLen
                                                                        : bodyCapacity;
            } else {
                ctx->bodyPayloadLength = 0;
            }
            if (!payloadOk) {
                break;
            }

            if (!HandleControlFrame(ctx, pipe, request)) {
                MarkBroken(pipe);
                break;
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        if (ctx->controlPipe == pipe) {
            ctx->controlPipe = INVALID_HANDLE_VALUE;
        }

        Sleep(kRetrySleepMs);
        ++attempts;
    }

    return 0;
}

DWORD WINAPI RecvThread(LPVOID parameter) {
    ServerContext* ctx = static_cast<ServerContext*>(parameter);
    while (!Stopped(ctx->stopEvent)) {
        HANDLE pipe = CreatePipeInstance(ctx->recvName);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(kRetrySleepMs);
            continue;
        }
        Sleep(kPreConnectDelayMs);
        if (!WaitForConnection(pipe, ctx->stopEvent)) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            continue;
        }
        SendHello(ctx, pipe, ctx->recvName, ctx->pid);
        ctx->recvPipe = pipe;
        while (!Stopped(ctx->stopEvent)) {
            Sleep(kQueueWaitMs);
            DWORD available = 0;
            if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
                break;
            }
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        if (ctx->recvPipe == pipe) {
            ctx->recvPipe = INVALID_HANDLE_VALUE;
        }
    }
    return 0;
}

DWORD WINAPI WriterThread(LPVOID parameter) {
    ServerContext* ctx = static_cast<ServerContext*>(parameter);
    uint8_t pending[kHeaderSize + 8192];
    size_t pendingLength = 0;
    bool hasPending = false;
    while (true) {
        bool stopping = Stopped(ctx->stopEvent);
        HANDLE pipe = ctx->recvPipe;
        if (pipe == INVALID_HANDLE_VALUE || pipe == nullptr) {
            if (stopping) {
                return 0;
            }
            if (ctx->workEvent != nullptr) {
                WaitForSingleObject(ctx->workEvent, kQueueWaitMs);
            } else {
                Sleep(kQueueWaitMs);
            }
            continue;
        }

        if (!hasPending) {
            if (ctx->queueLockReady) {
                EnterCriticalSection(&ctx->queueLock);
                if (ctx->sendQueueCount != 0) {
                    size_t slot = ctx->sendQueueHead;
                    size_t length = ctx->sendQueueLength[slot];
                    if (length <= sizeof(pending)) {
                        for (size_t i = 0; i < length; ++i) {
                            pending[i] = ctx->sendQueue[slot][i];
                        }
                        pendingLength = length;
                        hasPending = true;
                    }
                    ctx->sendQueueHead = (ctx->sendQueueHead + 1) % kMaxQueueItems;
                    ctx->sendQueueCount--;
                }
                LeaveCriticalSection(&ctx->queueLock);
            }
        }

        if (!hasPending) {
            if (stopping) {
                return 0;
            }
            if (ctx->workEvent != nullptr) {
                WaitForSingleObject(ctx->workEvent, kQueueWaitMs);
            } else {
                Sleep(kQueueWaitMs);
            }
            continue;
        }

        if (WriteExact(pipe, pending, pendingLength)) {
            hasPending = false;
            pendingLength = 0;
        } else {
            MarkBroken(pipe);
            if (stopping) {
                return 0;
            }
            if (ctx->workEvent != nullptr) {
                WaitForSingleObject(ctx->workEvent, kQueueWaitMs);
            } else {
                Sleep(kQueueWaitMs);
            }
        }
    }
}

}