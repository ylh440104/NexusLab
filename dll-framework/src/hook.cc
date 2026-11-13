#include "hook.h"

namespace nexuslab {

namespace {

void WriteU64(unsigned char* target, unsigned long long value) {
    for (int index = 0; index < 8; ++index) {
        target[index] = static_cast<unsigned char>((value >> (index * 8)) & 0xFF);
    }
}

bool IsRipRelative(const unsigned char* code, size_t index, size_t* instructionEnd) {
    unsigned char modrm = code[index + 2];
    unsigned char mod = modrm >> 6;
    unsigned char rm = modrm & 0x07;

    if (mod == 0 && rm == 5) {
        return true;
    }

    size_t length = 3;
    bool hasSib = (rm == 4);

    if (hasSib) {
        unsigned char sib = code[index + 3];
        unsigned char base = sib & 0x07;
        if (mod == 0 && base == 5) {
            return true;
        }
        length += 1;
    }

    if (mod == 2) {
        length += 4;
    } else if (mod == 1) {
        length += 1;
    }

    *instructionEnd = index + length;
    return false;
}

}

size_t HookMeasurePrologue(const unsigned char* code, size_t minimum, size_t limit) {
    if (code == nullptr || limit == 0) {
        return 0;
    }

    size_t index = 0;

    while (index < limit && index < minimum) {
        unsigned char first = code[index];

        if (first >= 0x50 && first <= 0x57) {
            ++index;
            continue;
        }

        if (first == 0x41) {
            unsigned char second = code[index + 1];
            if (second >= 0x50 && second <= 0x57) {
                index += 2;
                continue;
            }
            return 0;
        }

        if (first == 0x48 && index + 4 <= limit) {
            unsigned char second = code[index + 1];

            if (second == 0x83 && code[index + 2] == 0xEC) {
                index += 4;
                continue;
            }

            if (second == 0x81 && code[index + 2] == 0xEC) {
                index += 7;
                continue;
            }

            if (second == 0x8D || second == 0x89 || second == 0x8B) {
                if (index + 4 > limit) {
                    return 0;
                }

                size_t end = 0;
                if (IsRipRelative(code, index, &end)) {
                    return 0;
                }

                if (end == 0) {
                    return 0;
                }

                index = end;
                continue;
            }
        }

        return 0;
    }

    if (index < kHookJumpSize) {
        return 0;
    }

    return index;
}

void HookInit(SendHook* hook) {
    hook->target = nullptr;
    hook->trampoline = nullptr;
    hook->patchLength = 0;
    hook->trampolineLength = 0;
    hook->capture = nullptr;
    hook->handler = nullptr;
    hook->installed = false;
    hook->lastError = 0;

    for (size_t index = 0; index < kHookMaxPrologue; ++index) {
        hook->savedBytes[index] = 0;
    }
}

unsigned long long HookCaptureSlot(const HookCapture* capture, size_t index) {
    if (capture == nullptr || index >= kMaxCapturedSlots) {
        return 0;
    }
    return static_cast<unsigned long long>(capture->slots[index]);
}

unsigned long long HookCaptureCount(const HookCapture* capture) {
    if (capture == nullptr) {
        return 0;
    }
    return static_cast<unsigned long long>(capture->count);
}

bool HookInstall(SendHook* hook, void* targetAddress, size_t prologueLength,
                 HookCapture* capture, size_t registerCount) {
    if (hook == nullptr || targetAddress == nullptr || capture == nullptr) {
        return false;
    }

    if (registerCount == 0 || registerCount > 4) {
        registerCount = 4;
    }

    if (hook->installed) {
        return true;
    }

    if (prologueLength < kHookJumpSize || prologueLength > kHookMaxPrologue) {
        hook->lastError = 13;
        return false;
    }

    unsigned char* target = static_cast<unsigned char*>(targetAddress);

    unsigned char* trampoline = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (trampoline == nullptr) {
        hook->lastError = GetLastError();
        return false;
    }

    size_t cursor = 0;
    for (size_t index = 0; index < prologueLength; ++index) {
        hook->savedBytes[index] = target[index];
        trampoline[cursor + index] = target[index];
    }
    cursor += prologueLength;

    if (hook->handler != nullptr) {
        static const unsigned char pushAll[11] = {
            0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53
        };
        for (size_t index = 0; index < sizeof(pushAll); ++index) {
            trampoline[cursor + index] = pushAll[index];
        }
        cursor += sizeof(pushAll);

        static const unsigned char subRsp[7] = { 0x48, 0x81, 0xEC, 0x60, 0x00, 0x00, 0x00 };
        for (size_t index = 0; index < sizeof(subRsp); ++index) {
            trampoline[cursor + index] = subRsp[index];
        }
        cursor += sizeof(subRsp);

        for (int slot = 0; slot < 6; ++slot) {
            trampoline[cursor + 0] = 0xF3;
            trampoline[cursor + 1] = 0x0F;
            trampoline[cursor + 2] = 0x7F;
            trampoline[cursor + 3] = 0x44;
            trampoline[cursor + 4] = 0x24;
            trampoline[cursor + 5] = static_cast<unsigned char>(slot * 16);
            cursor += 6;
        }

        static const unsigned char movRcx[8] = { 0x48, 0x8B, 0x8C, 0x24, 0x88, 0x00, 0x00, 0x00 };
        static const unsigned char movRdx[8] = { 0x48, 0x8B, 0x94, 0x24, 0x80, 0x00, 0x00, 0x00 };
        static const unsigned char movR8[8] = { 0x4C, 0x8B, 0x84, 0x24, 0x78, 0x00, 0x00, 0x00 };
        static const unsigned char movR9[8] = { 0x4C, 0x8B, 0x8C, 0x24, 0x70, 0x00, 0x00, 0x00 };
        const unsigned char* moves[4];
        moves[0] = movRcx;
        moves[1] = movRdx;
        moves[2] = movR8;
        moves[3] = movR9;
        for (int slot = 0; slot < 4; ++slot) {
            for (size_t index = 0; index < 8; ++index) {
                trampoline[cursor + index] = moves[slot][index];
            }
            cursor += 8;
        }

        trampoline[cursor + 0] = 0x48;
        trampoline[cursor + 1] = 0xB8;
        WriteU64(trampoline + cursor + 2,
                 reinterpret_cast<unsigned long long>(hook->handler));
        cursor += 10;

        trampoline[cursor + 0] = 0xFF;
        trampoline[cursor + 1] = 0xD0;
        cursor += 2;

        for (int slot = 0; slot < 6; ++slot) {
            trampoline[cursor + 0] = 0xF3;
            trampoline[cursor + 1] = 0x0F;
            trampoline[cursor + 2] = 0x6F;
            trampoline[cursor + 3] = 0x44;
            trampoline[cursor + 4] = 0x24;
            trampoline[cursor + 5] = static_cast<unsigned char>(slot * 16);
            cursor += 6;
        }

        static const unsigned char addRsp[7] = { 0x48, 0x81, 0xC4, 0x60, 0x00, 0x00, 0x00 };
        for (size_t index = 0; index < sizeof(addRsp); ++index) {
            trampoline[cursor + index] = addRsp[index];
        }
        cursor += sizeof(addRsp);

        static const unsigned char popHigh[8] = { 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58 };
        for (size_t index = 0; index < sizeof(popHigh); ++index) {
            trampoline[cursor + index] = popHigh[index];
        }
        cursor += sizeof(popHigh);

        static const unsigned char popLow[3] = { 0x5A, 0x59, 0x58 };
        for (size_t index = 0; index < sizeof(popLow); ++index) {
            trampoline[cursor + index] = popLow[index];
        }
        cursor += sizeof(popLow);
    }

    trampoline[cursor + 0] = 0x50;
    cursor += 1;

    {
        static const unsigned char movRcx[3] = { 0x48, 0x89, 0x08 };
        static const unsigned char movRdx[3] = { 0x48, 0x89, 0x10 };
        static const unsigned char movR8[3] = { 0x4C, 0x89, 0x00 };
        static const unsigned char movR9[3] = { 0x4C, 0x89, 0x08 };
        const unsigned char* moves[4];
        moves[0] = movRcx;
        moves[1] = movRdx;
        moves[2] = movR8;
        moves[3] = movR9;

        for (size_t slot = 0; slot < registerCount; ++slot) {
            trampoline[cursor + 0] = 0x48;
            trampoline[cursor + 1] = 0xB8;
            WriteU64(trampoline + cursor + 2,
                     reinterpret_cast<unsigned long long>(&capture->slots[slot]));
            trampoline[cursor + 10] = moves[slot][0];
            trampoline[cursor + 11] = moves[slot][1];
            trampoline[cursor + 12] = moves[slot][2];
            cursor += 13;
        }
    }

    trampoline[cursor + 0] = 0x48;
    trampoline[cursor + 1] = 0xB8;
    WriteU64(trampoline + cursor + 2,
             reinterpret_cast<unsigned long long>(&capture->count));
    trampoline[cursor + 10] = 0x48;
    trampoline[cursor + 11] = 0xFF;
    trampoline[cursor + 12] = 0x00;
    cursor += 13;

    trampoline[cursor + 0] = 0x58;
    cursor += 1;

    trampoline[cursor + 0] = 0xFF;
    trampoline[cursor + 1] = 0x25;
    trampoline[cursor + 2] = 0x00;
    trampoline[cursor + 3] = 0x00;
    trampoline[cursor + 4] = 0x00;
    trampoline[cursor + 5] = 0x00;
    WriteU64(trampoline + cursor + 6,
             reinterpret_cast<unsigned long long>(target + prologueLength));
    cursor += 14;

    hook->trampolineLength = cursor;

    unsigned char patch[kHookMaxPrologue];

    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    WriteU64(patch + 6, reinterpret_cast<unsigned long long>(trampoline));

    for (size_t index = kHookJumpSize; index < prologueLength; ++index) {
        patch[index] = 0x90;
    }

    DWORD oldProtect = 0;

    if (!VirtualProtect(target, prologueLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        hook->lastError = GetLastError();
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }

    for (size_t index = 0; index < prologueLength; ++index) {
        target[index] = patch[index];
    }

    DWORD ignored = 0;
    VirtualProtect(target, prologueLength, oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), target, prologueLength);

    hook->target = target;
    hook->trampoline = trampoline;
    hook->patchLength = prologueLength;
    hook->capture = capture;
    hook->installed = true;

    return true;
}

bool HookUninstall(SendHook* hook) {
    if (hook == nullptr || !hook->installed) {
        return false;
    }

    DWORD oldProtect = 0;

    if (!VirtualProtect(hook->target, hook->patchLength, PAGE_EXECUTE_READWRITE,
                        &oldProtect)) {
        hook->lastError = GetLastError();
        return false;
    }

    for (size_t index = 0; index < hook->patchLength; ++index) {
        hook->target[index] = hook->savedBytes[index];
    }

    DWORD ignored = 0;
    VirtualProtect(hook->target, hook->patchLength, oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), hook->target, hook->patchLength);

    if (hook->trampoline != nullptr) {
        VirtualFree(hook->trampoline, 0, MEM_RELEASE);
    }

    hook->installed = false;

    return true;
}

}