#include "inline_hook.h"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

namespace nexuslab_inline {
namespace {

struct Patch {
    unsigned char* target;
    unsigned char saved[32];
    size_t savedLength;
    unsigned char* trampoline;
    size_t trampolineSize;
};

std::vector<Patch> g_patches;

constexpr size_t kAbsJumpSize = 14;

size_t PageSize() {
    static const size_t size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    return size == 0 ? 4096 : size;
}

bool MakeWritable(void* address, size_t length) {
    const uintptr_t start = reinterpret_cast<uintptr_t>(address) & ~(PageSize() - 1);
    const uintptr_t end = (reinterpret_cast<uintptr_t>(address) + length + PageSize() - 1) & ~(PageSize() - 1);
    return ::mprotect(reinterpret_cast<void*>(start), end - start,
                      PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

bool MakeExecutable(void* address, size_t length) {
    const uintptr_t start = reinterpret_cast<uintptr_t>(address) & ~(PageSize() - 1);
    const uintptr_t end = (reinterpret_cast<uintptr_t>(address) + length + PageSize() - 1) & ~(PageSize() - 1);
    return ::mprotect(reinterpret_cast<void*>(start), end - start,
                      PROT_READ | PROT_EXEC) == 0;
}

// Minimal x86-64 length decoder: handles the prologue instructions we meet.
size_t InstructionLength(const unsigned char* code) {
    size_t index = 0;
    bool operand16 = false;
    bool rexW = false;

    while (index < 15) {
        const unsigned char byte = code[index];
        if (byte == 0x66) { operand16 = true; index++; continue; }
        if (byte == 0x67) { index++; continue; }
        if (byte == 0xF0 || byte == 0xF2 || byte == 0xF3) { index++; continue; }
        if (byte == 0x2E || byte == 0x36 || byte == 0x3E || byte == 0x26 ||
            byte == 0x64 || byte == 0x65) { index++; continue; }
        if (byte >= 0x40 && byte <= 0x4F) { rexW = (byte & 0x08) != 0; index++; continue; }
        break;
    }
    if (index >= 15) return 0;

    const unsigned char opcode = code[index];

    if (opcode >= 0x50 && opcode <= 0x5F) return index + 1;  // push/pop reg
    if (opcode >= 0x90 && opcode <= 0x97) return index + 1;  // xchg/nop
    if (opcode == 0xE8 || opcode == 0xE9) return index + 5;
    if (opcode == 0xEB) return index + 2;
    if (opcode >= 0x70 && opcode <= 0x7F) return index + 2;
    if (opcode == 0x0F && index + 1 < 16) {
        const unsigned char op2 = code[index + 1];
        if (op2 >= 0x80 && op2 <= 0x8F) return index + 6;
        return index + 2 + 4;
    }
    if (opcode >= 0xB8 && opcode <= 0xBF) return index + 1 + (rexW ? 8 : 4);
    if (opcode == 0xC7) {
        const unsigned char modrm = code[index + 1];
        size_t size = index + 2;
        const unsigned char mod = modrm >> 6;
        const unsigned char rm = modrm & 7;
        if (mod != 3) {
            if (rm == 4) size += 1;
            if (mod == 0 && rm == 5) size += 4;
            else if (mod == 1) size += 1;
            else if (mod == 2) size += 4;
        }
        return size + 4;
    }
    if (opcode == 0x6A) return index + 2;
    if (opcode >= 0xB0 && opcode <= 0xB7) return index + 2;
    if (opcode == 0xC3) return index + 1;
    if (opcode <= 0x3F) return index + 1;
    if (opcode == 0x83) {
        const unsigned char modrm = code[index + 1];
        const unsigned char mod = modrm >> 6;
        const unsigned char rm = modrm & 7;
        size_t size = index + 2;
        if (mod != 3) {
            if (rm == 4) size += 1;
            if (mod == 0 && rm == 5) size += 4;
            else if (mod == 1) size += 1;
            else if (mod == 2) size += 4;
        }
        return size + 1;
    }

    // Generic fallback: opcode + modrm(+sib+disp)
    size_t size = index + 1;
    const unsigned char modrm = code[size];
    const unsigned char mod = modrm >> 6;
    const unsigned char reg = (modrm >> 3) & 7;
    const unsigned char rm = modrm & 7;
    size += 1;

    if (opcode == 0x05) return index + 5;
    if (opcode == 0x68) return index + 5;

    if (!(opcode == 0x88 || opcode == 0x89 || opcode == 0x8A || opcode == 0x8B ||
          opcode == 0x83 || opcode == 0x81 || opcode == 0x85 || opcode == 0xC6 ||
          opcode == 0x84 || opcode == 0x8D || opcode == 0x29 || opcode == 0x01 ||
          opcode == 0x3B || opcode == 0x39 || opcode == 0xFF || opcode == 0x50)) {
        return 0;
    }

    if (rm == 4) {
        size += 1;
        const unsigned char sib = code[size - 1];
        if (mod == 0 && (sib & 7) == 5) size += 4;
    }
    if (mod == 0 && rm == 5) size += 4;
    else if (mod == 1) size += 1;
    else if (mod == 2) size += 4;

    if (opcode == 0x83) size += 1;
    else if (opcode == 0x81) size += 4;
    (void)reg;
    return size;
}

// Detects instructions whose meaning depends on the instruction pointer.
// Copying them verbatim into a trampoline would break their displacement.
bool UsesRipRelative(const unsigned char* code, size_t length) {
    size_t index = 0;
    while (index < length) {
        if (code[index] >= 0x40 && code[index] <= 0x4F) { index++; continue; }
        if (code[index] == 0x66 || code[index] == 0x67 || code[index] == 0xF2 || code[index] == 0xF3) {
            index++;
            continue;
        }
        const unsigned char opcode = code[index];
        // opcode with modrm that may encode [rip+disp32]: mod==00 and rm==101
        const bool hasModrm = (opcode == 0x8B || opcode == 0x8D || opcode == 0x89 ||
                               opcode == 0x8A || opcode == 0x88 || opcode == 0xC7 ||
                               opcode == 0x81 || opcode == 0x83 || opcode == 0x85 ||
                               opcode == 0x3B || opcode == 0x39 || opcode == 0x01 ||
                               opcode == 0x29 || opcode == 0x03 || opcode == 0x0B ||
                               opcode == 0xFF || opcode == 0xB8);
        if (hasModrm && index + 1 < length) {
            const unsigned char modrm = code[index + 1];
            if (((modrm >> 6) == 0) && ((modrm & 7) == 5)) {
                return true;
            }
        }
        if (opcode == 0x0F) {
            return true;  // conservatively treat multi-byte opcodes as unsafe
        }
        return false;
    }
    return false;
}

bool FlushInstructionCache(void* address, size_t length) {
    void* start = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) & ~static_cast<uintptr_t>(63));
    void* end = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) + length);
    return ::mprotect(start, reinterpret_cast<uintptr_t>(end) - reinterpret_cast<uintptr_t>(start),
                      PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

}  // namespace

bool Install(void* target, void* replacement, void** trampolineOut) {
    if (target == nullptr || replacement == nullptr) {
        return false;
    }
    unsigned char* code = static_cast<unsigned char*>(target);

    size_t required = 0;
    size_t cursor = 0;
    while (required < kAbsJumpSize) {
        const size_t length = InstructionLength(code + cursor);
        if (length == 0 || length > 15) {
            char dump[128];
            const int written = std::snprintf(dump, sizeof(dump),
                "[inline] decode failed at +%zu, bytes:",
                cursor);
            const int fd = ::open("/tmp/nexuslab-napi-hook.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
            if (fd >= 0) {
                ::write(fd, dump, static_cast<size_t>(written));
                for (size_t i = 0; i < 16; ++i) {
                    char byteText[8];
                    const int n = std::snprintf(byteText, sizeof(byteText), " %02x", code[cursor + i]);
                    ::write(fd, byteText, static_cast<size_t>(n));
                }
                ::write(fd, "\n", 1);
                ::close(fd);
            }
            return false;
        }
        required += length;
        cursor += length;
        if (cursor > 32) {
            return false;
        }
    }

    if (UsesRipRelative(code, required)) {
        const int fd = ::open("/tmp/nexuslab-napi-hook.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd >= 0) {
            const char* message = "[inline] refuse: rip-relative in prologue
";
            ::write(fd, message, std::strlen(message));
            ::close(fd);
        }
        return false;
    }

    const size_t pageSize = PageSize();
    const size_t trampolineSize = required + kAbsJumpSize + pageSize;
    void* buffer = ::mmap(nullptr, trampolineSize, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED) {
        return false;
    }

    unsigned char* trampoline = static_cast<unsigned char*>(buffer);
    std::memcpy(trampoline, code, required);

    unsigned char* back = trampoline + required;
    back[0] = 0x48; back[1] = 0xB8;
    const uint64_t returnAddress = reinterpret_cast<uint64_t>(code + required);
    std::memcpy(back + 2, &returnAddress, 8);
    back[10] = 0xFF; back[11] = 0xE0;

    if (::mprotect(buffer, trampolineSize, PROT_READ | PROT_EXEC) != 0) {
        ::munmap(buffer, trampolineSize);
        return false;
    }

    if (!MakeWritable(code, required)) {
        ::munmap(buffer, trampolineSize);
        return false;
    }

    Patch patch;
    patch.target = code;
    patch.savedLength = required;
    std::memcpy(patch.saved, code, required);
    patch.trampoline = trampoline;
    patch.trampolineSize = trampolineSize;

    code[0] = 0x48; code[1] = 0xB8;
    const uint64_t hookAddress = reinterpret_cast<uint64_t>(replacement);
    std::memcpy(code + 2, &hookAddress, 8);
    code[10] = 0xFF; code[11] = 0xE0;
    for (size_t i = kAbsJumpSize; i < required; ++i) {
        code[i] = 0x90;
    }

    FlushInstructionCache(code, required);
    MakeExecutable(code, required);

    g_patches.push_back(patch);
    if (trampolineOut != nullptr) {
        *trampolineOut = trampoline;
    }
    return true;
}

void RemoveAll() {
    for (auto& patch : g_patches) {
        if (MakeWritable(patch.target, patch.savedLength)) {
            std::memcpy(patch.target, patch.saved, patch.savedLength);
            FlushInstructionCache(patch.target, patch.savedLength);
        }
        ::munmap(patch.trampoline, patch.trampolineSize);
    }
    g_patches.clear();
}

}  // namespace nexuslab_inline
