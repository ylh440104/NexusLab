#include "protocol.h"

namespace nexuslab {

void WriteU16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
}

void WriteU32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

void WriteU64(uint8_t* p, uint64_t v) {
    WriteU32(p, static_cast<uint32_t>(v & 0xffffffffu));
    WriteU32(p + 4, static_cast<uint32_t>((v >> 32) & 0xffffffffu));
}

uint16_t ReadU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadU64(const uint8_t* p) {
    const uint64_t lo = ReadU32(p);
    const uint64_t hi = ReadU32(p + 4);
    return lo | (hi << 32);
}

size_t EncodeHeader(const FrameHeader& header, uint8_t* out) {
    WriteU32(out + 0, kPipeMagic);
    WriteU16(out + 4, kPipeVersion);
    WriteU16(out + 6, header.op);
    WriteU32(out + 8, header.requestId);
    WriteU32(out + 12, static_cast<uint32_t>(header.status));
    WriteU32(out + 16, header.flags);
    WriteU32(out + 20, header.cmdLen);
    WriteU32(out + 24, header.msgLen);
    WriteU32(out + 28, header.bodyLen);
    WriteU64(out + 32, header.value0);
    return kHeaderSize;
}

bool DecodeHeader(const uint8_t* data, size_t size, FrameHeader* header) {
    if (size < kHeaderSize) {
        return false;
    }

    header->magic = ReadU32(data + 0);
    header->version = ReadU16(data + 4);
    header->op = ReadU16(data + 6);
    header->requestId = ReadU32(data + 8);
    header->status = static_cast<int32_t>(ReadU32(data + 12));
    header->flags = ReadU32(data + 16);
    header->cmdLen = ReadU32(data + 20);
    header->msgLen = ReadU32(data + 24);
    header->bodyLen = ReadU32(data + 28);
    header->value0 = ReadU64(data + 32);

    if (header->magic != kPipeMagic) {
        return false;
    }
    if (header->version != kPipeVersion) {
        return false;
    }

    return FrameLimitsOk(*header);
}

bool FrameLimitsOk(const FrameHeader& header) {
    if (header.cmdLen > kMaxCmd) {
        return false;
    }
    if (header.msgLen > kMaxMsg) {
        return false;
    }
    if (header.bodyLen > kMaxBody) {
        return false;
    }
    return true;
}

namespace {

size_t AppendLiteral(char* buffer, size_t cursor, size_t capacity, const char* text) {
    for (size_t i = 0; text[i] != 0 && cursor + 1 < capacity; ++i) {
        buffer[cursor++] = text[i];
    }
    if (cursor < capacity) {
        buffer[cursor] = 0;
    }
    return cursor;
}

size_t AppendDecimal(char* buffer, size_t cursor, size_t capacity, DWORD value) {
    char digits[16];
    int count = 0;

    if (value == 0) {
        digits[count++] = '0';
    } else {
        while (value != 0 && count < 16) {
            digits[count++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        }
    }

    while (count > 0 && cursor + 1 < capacity) {
        buffer[cursor++] = digits[--count];
    }
    if (cursor < capacity) {
        buffer[cursor] = 0;
    }
    return cursor;
}

}

size_t BuildPipeName(char* buffer, size_t capacity, DWORD pid, const char* suffix) {
    if (buffer == nullptr || capacity == 0) {
        return 0;
    }

    buffer[0] = 0;
    size_t cursor = 0;
    cursor = AppendLiteral(buffer, cursor, capacity, "\\\\.\\pipe\\mojo.");
    cursor = AppendDecimal(buffer, cursor, capacity, pid);
    cursor = AppendLiteral(buffer, cursor, capacity, ".");
    cursor = AppendLiteral(buffer, cursor, capacity, suffix);
    return cursor;
}

}