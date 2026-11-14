#include "core.h"

#include <dlfcn.h>
#include <elf.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstdio>
#include <cstring>

namespace nexuslab_linux {

namespace {

#if defined(__aarch64__)
constexpr size_t kIndirectCallRegister = 6;
#else
constexpr size_t kIndirectCallRegister = 3;
#endif
constexpr size_t kMaxArguments = 6;
#if defined(__aarch64__)
constexpr unsigned int kTrapInstruction = 0xD4200000U;
constexpr size_t kTrapWidth = 4;
#else
constexpr unsigned int kTrapInstruction = 0xCCU;
constexpr size_t kTrapWidth = 1;
#endif
constexpr unsigned long kMinValidStack = 0x10000UL;
constexpr int kMaxSteps = 4096;

#if defined(__aarch64__)

struct RemoteRegisters {
    unsigned long long gpr[34];
};

unsigned long long& ProgramCounter(RemoteRegisters& registers) {
    return registers.gpr[32];
}

unsigned long long& StackPointer(RemoteRegisters& registers) {
    return registers.gpr[31];
}

unsigned long long& ReturnValue(RemoteRegisters& registers) {
    return registers.gpr[0];
}

unsigned long long& ArgumentRegister(RemoteRegisters& registers, size_t index) {
    return registers.gpr[index];
}
unsigned long long& IndirectTarget(RemoteRegisters& registers) {
    return registers.gpr[kIndirectCallRegister];
}
unsigned long long& SyscallNumber(RemoteRegisters& registers) {
    return registers.gpr[8];
}
unsigned long long& SyscallArgumentRegister(RemoteRegisters& registers, size_t index) {
    return registers.gpr[index];
}
unsigned long long& LinkRegister(RemoteRegisters& registers) {
    return registers.gpr[30];
}

bool ReadRegisters(pid_t pid, RemoteRegisters* out) {
    struct iovec vector;
    vector.iov_base = out->gpr;
    vector.iov_len = sizeof(out->gpr);
    return ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &vector) == 0;
}

bool WriteRegisters(pid_t pid, const RemoteRegisters& registers) {
    struct iovec vector;
    vector.iov_base = const_cast<unsigned long long*>(registers.gpr);
    vector.iov_len = sizeof(registers.gpr);
    return ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &vector) == 0;
}

#else

struct RemoteRegisters {
    struct user_regs_struct native;
};

unsigned long long& ProgramCounter(RemoteRegisters& registers) {
    return registers.native.rip;
}

unsigned long long& StackPointer(RemoteRegisters& registers) {
    return registers.native.rsp;
}

unsigned long long& ReturnValue(RemoteRegisters& registers) {
    return registers.native.rax;
}

unsigned long long& ArgumentRegister(RemoteRegisters& registers, size_t index) {
    switch (index) {
        case 0:
            return registers.native.rdi;
        case 1:
            return registers.native.rsi;
        case 2:
            return registers.native.rdx;
        case 3:
            return registers.native.rcx;
        case 4:
            return registers.native.r8;
        default:
            return registers.native.r9;
    }
}

unsigned long long& IndirectTarget(RemoteRegisters& registers) {
    return registers.native.rbx;
}
unsigned long long& SyscallNumber(RemoteRegisters& registers) {
    return registers.native.rax;
}

unsigned long long& LinkRegister(RemoteRegisters& registers) {
    return registers.native.rsp;
}

unsigned long long& SyscallArgumentRegister(RemoteRegisters& registers, size_t index) {
    switch (index) {
        case 0:
            return registers.native.rdi;
        case 1:
            return registers.native.rsi;
        case 2:
            return registers.native.rdx;
        case 3:
            return registers.native.r10;
        case 4:
            return registers.native.r8;
        default:
            return registers.native.r9;
    }
}

bool ReadRegisters(pid_t pid, RemoteRegisters* out) {
    return ptrace(PTRACE_GETREGS, pid, nullptr, &out->native) == 0;
}

bool WriteRegisters(pid_t pid, const RemoteRegisters& registers) {
    struct user_regs_struct copy = registers.native;
    return ptrace(PTRACE_SETREGS, pid, nullptr, &copy) == 0;
}

#endif

bool WaitForStop(pid_t pid, int* outStatus) {
    for (;;) {
        int status = 0;
        pid_t waited = waitpid(pid, &status, __WALL);
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (WIFSTOPPED(status)) {
            if (outStatus != nullptr) {
                *outStatus = status;
            }
            return true;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            return false;
        }
        }
    }

void UndoBreakpoint(pid_t pid, unsigned long long returnAddress, const unsigned char* originalBytes,
                    unsigned long long scratchStack, const unsigned char* snapshot) {
    WriteProcessMemory(pid, returnAddress, originalBytes, kTrapWidth);
    WriteProcessMemory(pid, scratchStack, snapshot, 16);
}

}

std::string g_lastError;


unsigned long long LocateSyscallInstruction(pid_t pid, unsigned long long functionEntry) {
    unsigned char window[128] = {0};
    if (!ReadProcessMemory(pid, functionEntry, window, sizeof(window))) {
        return 0;
    }

#if defined(__aarch64__)
    for (size_t offset = 0; offset + 4 <= sizeof(window); offset += 4) {
        const unsigned int instruction =
            static_cast<unsigned int>(window[offset]) |
            (static_cast<unsigned int>(window[offset + 1]) << 8) |
            (static_cast<unsigned int>(window[offset + 2]) << 16) |
            (static_cast<unsigned int>(window[offset + 3]) << 24);
        if (instruction == 0xD4000001U) {
            return functionEntry + offset;
        }
    }
#else
    for (size_t offset = 0; offset + 2 <= sizeof(window); ++offset) {
        if (window[offset] == 0x0F && window[offset + 1] == 0x05) {
            return functionEntry + offset;
        }
    }
#endif

    return 0;
}

unsigned long long AllocateScratchStack(pid_t pid, unsigned long long nearAddress) {
#if defined(__aarch64__)
    constexpr unsigned long long kMmapSyscall = 222;
#else
    constexpr unsigned long long kMmapSyscall = 9;
#endif
    constexpr unsigned long long kStackSize = 64 * 1024;
    constexpr unsigned long long kMapPrivateAnonymous = 0x02 | 0x20;

    (void)nearAddress;
    const std::vector<unsigned long long> arguments = {
        0,
        kStackSize,
        3,
        static_cast<unsigned long long>(kMapPrivateAnonymous),
        static_cast<unsigned long long>(-1LL),
        0,
    };

    unsigned long long base = 0;
    if (!CallRemoteSyscall(pid, kMmapSyscall, arguments, &base)) {
        return 0;
    }
    if (static_cast<long long>(base) < 0) {
        return 0;
    }
#if defined(__aarch64__)
    return (base + kStackSize) & ~0xFULL;
#else
    return ((base + kStackSize) & ~0xFULL) - 8;
#endif
}

namespace {

constexpr unsigned int kBreakInstruction = 0xD4200000U;
constexpr unsigned long long kRemoteStackSize = 2ULL * 1024 * 1024;

unsigned long long g_codeSlot = 0;
unsigned long long g_stackTop = 0;
pid_t g_reservedPid = 0;

std::string ToHex(unsigned long long value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", value);
    return std::string(buffer);
}

bool RemoteMapMemory(pid_t pid, unsigned long long length, int protection, int flags,
                     unsigned long long* outAddress) {
#if defined(__aarch64__)
    constexpr unsigned long long kMmapSyscall = 222;
#else
    constexpr unsigned long long kMmapSyscall = 9;
#endif
    const std::vector<unsigned long long> arguments = {
        0,
        length,
        static_cast<unsigned long long>(protection),
        static_cast<unsigned long long>(flags),
        static_cast<unsigned long long>(-1LL),
        0,
    };
    unsigned long long result = 0;
    if (!CallRemoteSyscall(pid, kMmapSyscall, arguments, &result)) {
        return false;
    }
    if (static_cast<long long>(result) < 0) {
        g_lastError = "remote mmap returned an error";
        return false;
    }
    *outAddress = result;
    return true;
}


unsigned long long EntryPointOf(pid_t pid, unsigned long long moduleBase) {
    unsigned char header[64] = {0};
    if (!ReadProcessMemory(pid, moduleBase, header, sizeof(header))) {
        return 0;
    }
    if (header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F') {
        return 0;
    }
    if (header[4] != 2) {
        return 0;
    }
    unsigned long long entry = 0;
    std::memcpy(&entry, header + 24, sizeof(entry));
    return entry;
}

bool MakeWritable(pid_t pid, unsigned long long address, unsigned long long length) {
#if defined(__aarch64__)
    constexpr unsigned long long kMprotectSyscall = 226;
#else
    constexpr unsigned long long kMprotectSyscall = 10;
#endif
    const unsigned long long pageStart = address & ~0xFFFULL;
    const unsigned long long pageEnd = (address + length + 0xFFFULL) & ~0xFFFULL;
    const std::vector<unsigned long long> arguments = {
        pageStart,
        pageEnd - pageStart,
        3,
    };
    unsigned long long result = 0;
    if (!CallRemoteSyscall(pid, kMprotectSyscall, arguments, &result)) {
        return false;
    }
    return result == 0;
}

constexpr unsigned long long kPathBufferSize = 4096;

unsigned long long EnsurePathBuffer(pid_t pid) {
    static pid_t cachedPid = 0;
    static unsigned long long cached = 0;
    if (cachedPid != pid) {
        cachedPid = pid;
        cached = 0;
    }
    if (cached != 0) {
        return cached;
    }
    unsigned long long slot = 0;
    if (!RemoteMapMemory(pid, kPathBufferSize, 3, 0x22, &slot)) {
        return 0;
    }
    cached = slot;
    return cached;
}

unsigned long long EnsureCodeSlot(pid_t pid) {
    if (g_reservedPid != pid) {
        g_codeSlot = 0;
        g_stackTop = 0;
        g_reservedPid = pid;
    }
    if (g_codeSlot != 0) {
        return g_codeSlot;
    }

    unsigned long long mapping = 0;
    if (!RemoteMapMemory(pid, 0x2000, 7, 0x22, &mapping)) {
        return 0;
    }

    unsigned long long protResult = 0;
#if defined(__aarch64__)
    constexpr unsigned long long kMprotectNr = 226;
#else
    constexpr unsigned long long kMprotectNr = 10;
#endif
    const std::vector<unsigned long long> protArgs = {mapping, 0x2000, 7};
    if (CallRemoteSyscall(pid, kMprotectNr, protArgs, &protResult) && protResult != 0) {
        g_lastError = "mprotect(rwx) failed for code slot " + ToHex(mapping);
        return 0;
    }

    g_codeSlot = mapping + 0x100;
    return g_codeSlot;
}

unsigned long long EnsureRemoteStack(pid_t pid) {
    if (g_reservedPid != pid) {
        g_codeSlot = 0;
        g_stackTop = 0;
        g_reservedPid = pid;
    }
    if (g_stackTop != 0) {
        return g_stackTop;
    }

    unsigned long long base = 0;
    if (!RemoteMapMemory(pid, kRemoteStackSize, 3, 0x22 | 0x100, &base)) {
        return 0;
    }
    g_stackTop = (base + kRemoteStackSize) & ~0xFULL;
    return g_stackTop;
}

}

bool CallRemoteFunction(pid_t pid, unsigned long long address,
                        const std::vector<unsigned long long>& args,
                        unsigned long long* outReturn) {
    if (address == 0) {
        g_lastError = "remote call target address is zero";
        return false;
    }

    const unsigned long long codeAddress = EnsureCodeSlot(pid);
    if (codeAddress == 0) {
        return false;
    }

    const unsigned long long stackTop = EnsureRemoteStack(pid);
    if (stackTop == 0) {
        return false;
    }

    RemoteRegisters saved;
    if (!ReadRegisters(pid, &saved)) {
        g_lastError = "cannot read target registers before remote call";
        return false;
    }

#if defined(__aarch64__)
    const unsigned int trampoline[2] = {0xD63F00C0U, kBreakInstruction};
#else
    const unsigned char trampoline[3] = {0xFF, 0xD3, 0xCC};
#endif

    if (!WriteProcessMemory(pid, codeAddress, trampoline, sizeof(trampoline))) {
        g_lastError = "cannot install trampoline into target";
        return false;
    }

    unsigned char verifyBytes[8] = {0};
    if (!ReadProcessMemory(pid, codeAddress, verifyBytes, sizeof(trampoline))) {
        g_lastError = "cannot read back trampoline at " + ToHex(codeAddress);
        return false;
    }
    if (std::memcmp(verifyBytes, trampoline, sizeof(trampoline)) != 0) {
        g_lastError = "trampoline read-back mismatch at " + ToHex(codeAddress);
        return false;
    }

    RemoteRegisters working = saved;
    for (size_t index = 0; index < args.size() && index < kMaxArguments; ++index) {
        ArgumentRegister(working, index) = args[index];
    }

    ProgramCounter(working) = codeAddress;
    StackPointer(working) = stackTop - 16;
    IndirectTarget(working) = address;
#if !defined(__aarch64__)
    working.native.orig_rax = static_cast<unsigned long long>(-1);
#endif
#if defined(__aarch64__)
    LinkRegister(working) = codeAddress;
#endif

    if (!WriteRegisters(pid, working)) {
        g_lastError = "cannot apply registers for remote call";
        return false;
    }

    RemoteRegisters verify;
    if (ReadRegisters(pid, &verify)) {
        if (ProgramCounter(verify) != codeAddress) {
            g_lastError = "register write mismatch: want pc=" + ToHex(codeAddress) +
                          " got pc=" + ToHex(ProgramCounter(verify));
            return false;
        }
    }

    bool completed = false;
    unsigned long long result = 0;

    for (int step = 0; step < kMaxSteps; ++step) {
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0) {
            WriteRegisters(pid, saved);
            g_lastError = "cannot resume target process for remote call";
            return false;
        }

        int status = 0;
        if (!WaitForStop(pid, &status)) {
            g_lastError = "target process exited during remote call";
            return false;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        const int signal = WSTOPSIG(status);
        if (signal != SIGTRAP) {
            if (signal == SIGSEGV || signal == SIGBUS || signal == SIGILL) {
                RemoteRegisters faultRegs;
                unsigned long long faultPc = 0;
                if (ReadRegisters(pid, &faultRegs)) {
                    faultPc = ProgramCounter(faultRegs);
                }
                WriteRegisters(pid, saved);
                g_lastError = "target faulted during remote call: signal=" +
                              std::to_string(signal) + " pc=" + ToHex(faultPc) +
                              " address=" + ToHex(address) +
                              " codeSlot=" + ToHex(codeAddress) +
                              " stackTop=" + ToHex(stackTop);
                return false;
            }
            continue;
        }

        RemoteRegisters probe;
        if (!ReadRegisters(pid, &probe)) {
            g_lastError = "cannot read target registers after remote call stop";
            return false;
        }

        const unsigned long long currentPc = ProgramCounter(probe);
        if (currentPc == codeAddress || currentPc == codeAddress + 4) {
            result = ReturnValue(probe);
            completed = true;
            break;
        }
    }

    WriteRegisters(pid, saved);

    if (!completed) {
        g_lastError = "remote call did not return to the trampoline";
        return false;
    }

    if (outReturn != nullptr) {
        *outReturn = result;
    }
    return true;
}


bool CallRemoteSyscall(pid_t pid, unsigned long long syscallNumber,
                       const std::vector<unsigned long long>& args,
                       unsigned long long* outReturn) {
    const unsigned long long syscallEntry = ResolveRemoteSymbol(pid, "syscall");
    if (syscallEntry == 0) {
        g_lastError = "cannot resolve libc syscall inside target";
        return false;
    }

    const unsigned long long svcAddress = LocateSyscallInstruction(pid, syscallEntry);
    if (svcAddress == 0) {
        g_lastError = "cannot locate svc instruction inside target libc";
        return false;
    }

    RemoteRegisters saved;
    if (!ReadRegisters(pid, &saved)) {
        g_lastError = "cannot read target registers before syscall";
        return false;
    }

    const unsigned long long previousStack = StackPointer(saved);
    if (previousStack <= kMinValidStack) {
        g_lastError = "target stack pointer looks invalid";
        return false;
    }

    const unsigned long long scratchStack = (previousStack & ~0xFUL) - 8;
    unsigned char stackSnapshot[16] = {0};
    if (!ReadProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot))) {
        g_lastError = "cannot snapshot target stack memory";
        return false;
    }

    RemoteRegisters working = saved;
    for (size_t index = 0; index < args.size() && index < kMaxArguments; ++index) {
        SyscallArgumentRegister(working, index) = args[index];
    }
    SyscallNumber(working) = syscallNumber;
    ProgramCounter(working) = svcAddress;
    StackPointer(working) = scratchStack;

    if (!WriteRegisters(pid, working)) {
        WriteProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot));
        g_lastError = "cannot apply registers for syscall";
        return false;
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) != 0) {
        WriteProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot));
        WriteRegisters(pid, saved);
        g_lastError = "cannot single step the syscall instruction";
        return false;
    }

    int status = 0;
    if (!WaitForStop(pid, &status)) {
        WriteProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot));
        g_lastError = "target process exited during syscall step";
        return false;
    }

    RemoteRegisters after;
    if (!ReadRegisters(pid, &after)) {
        WriteProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot));
        g_lastError = "cannot read target registers after syscall step";
        return false;
    }

    const unsigned long long syscallResult = ReturnValue(after);

    WriteRegisters(pid, saved);
    WriteProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot));

    if (!WIFSTOPPED(status)) {
        g_lastError = "target did not stop after syscall step";
        return false;
    }

    if (outReturn != nullptr) {
        *outReturn = syscallResult;
    }
    return true;
}

bool InjectLibrary(pid_t pid, const std::string& libraryPath, unsigned long long* outHandle,
                   unsigned long long* outBase) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        g_lastError = "ptrace attach rejected (need matching uid or CAP_SYS_PTRACE)";
        return false;
    }
    int status = 0;
    if (!WaitForStop(pid, &status)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "target did not stop after attach";
        return false;
    }

    const unsigned long long dlopenAddress = ResolveRemoteSymbol(pid, "dlopen");
    if (dlopenAddress == 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "cannot resolve dlopen inside target";
        return false;
    }
    const unsigned long long dlerrorAddress = ResolveRemoteSymbol(pid, "dlerror");

    unsigned long long pathSlot = 0;
    {
        const std::vector<unsigned long long> mapArguments = {
            0, 4096, 3, 0x22, static_cast<unsigned long long>(-1LL), 0};
#if defined(__aarch64__)
        constexpr unsigned long long kMmapNr = 222;
#else
        constexpr unsigned long long kMmapNr = 9;
#endif
        if (!CallRemoteSyscall(pid, kMmapNr, mapArguments, &pathSlot)) {
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            g_lastError = "cannot allocate a path buffer inside target";
            return false;
        }
    }
    if (pathSlot == 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "cannot allocate a path buffer inside target";
        return false;
    }
    const size_t pathLength = libraryPath.size() + 1;
    if (pathLength > kPathBufferSize) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "library path is too long for the remote buffer";
        return false;
    }
    if (!WriteProcessMemory(pid, pathSlot, libraryPath.c_str(), pathLength)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "cannot write library path into target";
        return false;
    }

    unsigned long long handle = 0;
    const std::vector<unsigned long long> callArguments = {pathSlot, RTLD_NOW};
    const bool called = CallRemoteFunction(pid, dlopenAddress, callArguments, &handle);

    if (!called) {
                ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    if (handle == 0) {
        std::string message = "dlopen returned null inside target";
        if (dlerrorAddress != 0) {
            unsigned long long errorPointer = 0;
            const std::vector<unsigned long long> noArguments;
            if (CallRemoteFunction(pid, dlerrorAddress, noArguments, &errorPointer) &&
                errorPointer != 0) {
                char buffer[512] = {0};
                if (ReadProcessMemory(pid, errorPointer, buffer, sizeof(buffer) - 1)) {
                    message += ": ";
                    message += buffer;
                }
            }
        }
                ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = message;
        return false;
    }


    if (outHandle != nullptr) {
        *outHandle = handle;
    }
    if (outBase != nullptr) {
        *outBase = FindModuleBase(pid, libraryPath.c_str());
    }
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return true;
}

}
