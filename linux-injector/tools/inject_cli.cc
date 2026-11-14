#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "../core.h"
#include "../core_elf.h"

namespace {

bool AttachTarget(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        std::printf("attach failed errno=%d\n", errno);
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, __WALL) < 0) {
        std::printf("attach wait failed errno=%d\n", errno);
        return false;
    }
    return WIFSTOPPED(status);
}

int RunSymbolProbe(pid_t pid, const char* symbol) {
    using namespace nexuslab_linux;

    const unsigned long long address = ResolveRemoteSymbol(pid, symbol);
    std::printf("symbol=%s address=0x%llx\n", symbol, address);
    if (address == 0) {
        std::printf("resolve failed: %s\n", g_lastError.c_str());
        return 1;
    }
    if (!AttachTarget(pid)) {
        return 1;
    }
    unsigned long long value = 0;
    const bool ok = CallRemoteFunction(pid, address, std::vector<unsigned long long>(), &value);
    std::printf("call ok=%d value=%llu expected_pid=%d error=%s\n", ok ? 1 : 0, value,
                static_cast<int>(pid), g_lastError.c_str());
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return ok ? 0 : 1;
}

int RunSymbolOnly(pid_t pid, const char* symbol) {
    using namespace nexuslab_linux;

    const unsigned long long address = ResolveRemoteSymbol(pid, symbol);
    std::printf("symbol=%s resolved=0x%llx\n", symbol, address);
    if (address == 0) {
        std::printf("resolve failed: %s\n", g_lastError.c_str());
        return 1;
    }
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        std::printf("attach failed errno=%d\n", errno);
        return 1;
    }
    int status = 0;
    if (waitpid(pid, &status, __WALL) < 0) {
        std::printf("wait failed errno=%d\n", errno);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }
    unsigned long long value = 0;
    const bool ok = CallRemoteFunction(pid, address, std::vector<unsigned long long>(), &value);
    std::printf("call ok=%d value=%llu expected=%d error=%s\n", ok ? 1 : 0, value,
                static_cast<int>(pid), g_lastError.c_str());
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return ok ? 0 : 1;
}

int RunManualInjection(pid_t pid, const char* libraryPath) {
    using namespace nexuslab_linux;

    unsigned long long base = 0;
    unsigned long long initializers = 0;
    const bool ok = InjectLibraryManual(pid, libraryPath, &base, &initializers);
    std::printf("manual ok=%d base=0x%llx initializers=%llu error=%s\n", ok ? 1 : 0, base,
                initializers, g_lastError.c_str());
    return ok ? 0 : 1;
}

int RunInjection(pid_t pid, const char* libraryPath) {
    using namespace nexuslab_linux;

    unsigned long long handle = 0;
    unsigned long long base = 0;
    const bool ok = InjectLibrary(pid, libraryPath, &handle, &base);
    std::printf("inject ok=%d handle=%lu base=0x%lx error=%s\n", ok ? 1 : 0, handle, base,
                g_lastError.c_str());
    return ok ? 0 : 1;
}

}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: %s <pid> <so-path> [--symbol NAME | --call NAME]\n", argv[0]);
        return 2;
    }
    const pid_t pid = static_cast<pid_t>(std::atoi(argv[1]));
    if (pid <= 0) {
        std::printf("invalid pid\n");
        return 2;
    }

    if (argc >= 5) {
        if (std::strcmp(argv[3], "--symbol") == 0) {
            return RunSymbolProbe(pid, argv[4]);
        }
        if (std::strcmp(argv[3], "--call") == 0) {
            return RunSymbolOnly(pid, argv[4]);
        }
    }

    if (argc >= 4 && std::strcmp(argv[2], "--manual") == 0) {
        return RunManualInjection(pid, argv[3]);
    }

    return RunInjection(pid, argv[2]);
}
