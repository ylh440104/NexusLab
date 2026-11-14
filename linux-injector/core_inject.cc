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
#include <cstring>

namespace nexuslab_linux {

namespace {

constexpr size_t kMaxArguments = 6;
constexpr unsigned long kTrapOpcode = 0xCC;
constexpr unsigned long kMinValidStack = 0x10000UL;
constexpr int kMaxSteps = 4096;

#if defined(__aarch64__)

struct RemoteRegisters {
    unsigned long gpr[34];
};

unsigned long& ProgramCounter(RemoteRegisters& registers) {
    return registers.gpr[32];
}

unsigned long& StackPointer(RemoteRegisters& registers) {
    return registers.gpr[31];
}

unsigned long& ReturnValue(RemoteRegisters& registers) {
    return registers.gpr[0];
}

unsigned long& ArgumentRegister(RemoteRegisters& registers, size_t index) {
    return registers.gpr[index];
}

bool ReadRegisters(pid_t pid, RemoteRegisters* out) {
    struct iovec vector;
    vector.iov_base = out->gpr;
    vector.iov_len = sizeof(out->gpr);
    return ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &vector) == 0;
}

bool WriteRegisters(pid_t pid, const RemoteRegisters& registers) {
    struct iovec vector;
    vector.iov_base = const_cast<unsigned long*>(registers.gpr);
    vector.iov_len = sizeof(registers.gpr);
    return ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &vector) == 0;
}

#else

struct RemoteRegisters {
    struct user_regs_struct native;
};

unsigned long& ProgramCounter(RemoteRegisters& registers) {
    return registers.native.rip;
}

unsigned long& StackPointer(RemoteRegisters& registers) {
    return registers.native.rsp;
}

unsigned long& ReturnValue(RemoteRegisters& registers) {
    return registers.native.rax;
}

unsigned long& ArgumentRegister(RemoteRegisters& registers, size_t index) {
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

void UndoBreakpoint(pid_t pid, unsigned long returnAddress, unsigned char originalByte,
                    unsigned long scratchStack, const unsigned char* snapshot) {
    WriteProcessMemory(pid, returnAddress, &originalByte, 1);
    WriteProcessMemory(pid, scratchStack, snapshot, 16);
}

}

std::string g_lastError;

bool CallRemoteFunction(pid_t pid, unsigned long address, const std::vector<unsigned long>& args,
                        unsigned long* outReturn) {
    RemoteRegisters saved;
    if (!ReadRegisters(pid, &saved)) {
        g_lastError = "cannot read target registers";
        return false;
    }

    const unsigned long returnAddress = ProgramCounter(saved);
    const unsigned long previousStack = StackPointer(saved);
    if (previousStack <= kMinValidStack) {
        g_lastError = "target stack pointer looks invalid";
        return false;
    }

    const unsigned long scratchStack = (previousStack & ~0xFUL) - 8;
    unsigned char stackSnapshot[16] = {0};
    if (!ReadProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot))) {
        g_lastError = "cannot snapshot target stack memory";
        return false;
    }

    const unsigned long syntheticReturn = returnAddress;
    if (!WriteProcessMemory(pid, scratchStack, &syntheticReturn, sizeof(syntheticReturn))) {
        g_lastError = "cannot install return address on target stack";
        return false;
    }

    unsigned char originalByte = 0;
    if (!ReadProcessMemory(pid, returnAddress, &originalByte, 1)) {
        WriteProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot));
        g_lastError = "cannot read instruction byte at return address";
        return false;
    }

    const unsigned char trapByte = static_cast<unsigned char>(kTrapOpcode);
    if (!WriteProcessMemory(pid, returnAddress, &trapByte, 1)) {
        WriteProcessMemory(pid, scratchStack, stackSnapshot, sizeof(stackSnapshot));
        g_lastError = "cannot install breakpoint in target";
        return false;
    }

    RemoteRegisters working = saved;
    for (size_t index = 0; index < args.size() && index < kMaxArguments; ++index) {
        ArgumentRegister(working, index) = args[index];
    }
    ProgramCounter(working) = address;
    StackPointer(working) = scratchStack;

    if (!WriteRegisters(pid, working)) {
        UndoBreakpoint(pid, returnAddress, originalByte, scratchStack, stackSnapshot);
        g_lastError = "cannot apply registers to target";
        return false;
    }

    bool completed = false;
    unsigned long result = 0;

    for (int step = 0; step < kMaxSteps; ++step) {
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0) {
            UndoBreakpoint(pid, returnAddress, originalByte, scratchStack, stackSnapshot);
            g_lastError = "cannot resume target process";
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

        int signal = WSTOPSIG(status);
        if (signal == SIGTRAP) {
            RemoteRegisters probe;
            if (!ReadRegisters(pid, &probe)) {
                UndoBreakpoint(pid, returnAddress, originalByte, scratchStack, stackSnapshot);
                g_lastError = "cannot read target registers after stop";
                return false;
            }
            const unsigned long currentPc = ProgramCounter(probe);
            if (currentPc == returnAddress + 1) {
                ProgramCounter(probe) = returnAddress;
                WriteRegisters(pid, probe);
                result = ReturnValue(probe);
                completed = true;
                break;
            }
            if (currentPc == returnAddress) {
                result = ReturnValue(probe);
                completed = true;
                break;
            }
            continue;
        }

        if (signal == SIGSEGV || signal == SIGBUS || signal == SIGILL || signal == SIGFPE) {
            RemoteRegisters faulted;
            unsigned long faultPc = 0;
            if (ReadRegisters(pid, &faulted)) {
                faultPc = ProgramCounter(faulted);
            }
            char detail[192];
            std::snprintf(detail, sizeof(detail), "signal=%d pc=0x%lx address=0x%lx", signal,
                          faultPc, address);
            UndoBreakpoint(pid, returnAddress, originalByte, scratchStack, stackSnapshot);
            g_lastError = std::string("target faulted during remote call: ") + detail;
            return false;
        }

        ptrace(PTRACE_CONT, pid, nullptr, signal);
    }

    UndoBreakpoint(pid, returnAddress, originalByte, scratchStack, stackSnapshot);

    if (!completed) {
        g_lastError = "remote call did not reach the return breakpoint";
        return false;
    }

    if (outReturn != nullptr) {
        *outReturn = result;
    }
    return true;
}

bool InjectLibrary(pid_t pid, const std::string& libraryPath, unsigned long* outHandle,
                   unsigned long* outBase) {
    const unsigned long dlopenAddress = ResolveRemoteSymbol(pid, "dlopen");
    if (dlopenAddress == 0) {
        g_lastError = "cannot resolve dlopen inside target";
        return false;
    }
    const unsigned long dlerrorAddress = ResolveRemoteSymbol(pid, "dlerror");

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

    RemoteRegisters entry;
    if (!ReadRegisters(pid, &entry)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "cannot read target registers after attach";
        return false;
    }

    const unsigned long pathSlot = (StackPointer(entry) - 8192) & ~0xFUL;
    if (pathSlot <= kMinValidStack) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "no usable scratch space on target stack";
        return false;
    }

    unsigned char pathSnapshot[512] = {0};
    const size_t pathLength = libraryPath.size() + 1;
    const size_t snapshotSize =
        pathLength < sizeof(pathSnapshot) ? pathLength : sizeof(pathSnapshot);

    if (!ReadProcessMemory(pid, pathSlot, pathSnapshot, snapshotSize)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "cannot snapshot scratch area on target stack";
        return false;
    }

    if (!WriteProcessMemory(pid, pathSlot, libraryPath.c_str(), pathLength)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "cannot write library path into target";
        return false;
    }

    unsigned long handle = 0;
    const std::vector<unsigned long> callArguments = {pathSlot, RTLD_NOW};
    const bool called = CallRemoteFunction(pid, dlopenAddress, callArguments, &handle);

    if (!called) {
        WriteProcessMemory(pid, pathSlot, pathSnapshot, snapshotSize);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }

    if (handle == 0) {
        std::string message = "dlopen returned null inside target";
        if (dlerrorAddress != 0) {
            unsigned long errorPointer = 0;
            const std::vector<unsigned long> noArguments;
            if (CallRemoteFunction(pid, dlerrorAddress, noArguments, &errorPointer) &&
                errorPointer != 0) {
                char buffer[512] = {0};
                if (ReadProcessMemory(pid, errorPointer, buffer, sizeof(buffer) - 1)) {
                    message += ": ";
                    message += buffer;
                }
            }
        }
        WriteProcessMemory(pid, pathSlot, pathSnapshot, snapshotSize);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = message;
        return false;
    }

    WriteProcessMemory(pid, pathSlot, pathSnapshot, snapshotSize);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    if (outHandle != nullptr) {
        *outHandle = handle;
    }
    if (outBase != nullptr) {
        *outBase = FindModuleBase(pid, libraryPath.c_str());
    }
    return true;
}

}
