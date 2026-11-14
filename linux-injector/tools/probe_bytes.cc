#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../core.h"

namespace {

void PrintBytes(const char* label, const unsigned char* bytes, size_t length) {
    std::printf("%s:", label);
    for (size_t index = 0; index < length; ++index) {
        std::printf(" %02x", bytes[index]);
    }
    std::printf("\n");
}

}

int main(int argc, char** argv) {
    using namespace nexuslab_linux;

    if (argc < 3) {
        std::printf("usage: %s <pid> <symbol>\n", argv[0]);
        return 2;
    }

    const pid_t pid = static_cast<pid_t>(std::atoi(argv[1]));
    const char* symbol = argv[2];
    if (pid <= 0) {
        std::printf("invalid pid\n");
        return 2;
    }

    void* localSymbol = dlsym(RTLD_DEFAULT, symbol);
    if (localSymbol == nullptr) {
        std::printf("local symbol not found\n");
        return 1;
    }

    Dl_info localInfo;
    if (dladdr(localSymbol, &localInfo) == 0) {
        std::printf("dladdr failed\n");
        return 1;
    }

    const unsigned long long localBase = reinterpret_cast<unsigned long long>(localInfo.dli_fbase);
    const unsigned long long localAddress = reinterpret_cast<unsigned long long>(localSymbol);
    const unsigned long long offset = localAddress - localBase;
    const unsigned long long remoteBase = FindModuleBase(pid, localInfo.dli_fname);

    std::printf("symbol=%s\n", symbol);
    std::printf("local_file=%s\n", localInfo.dli_fname);
    std::printf("local_base=0x%llx local_addr=0x%llx offset=0x%llx\n", localBase, localAddress, offset);
    std::printf("remote_base=0x%llx remote_addr=0x%llx\n", remoteBase, remoteBase + offset);

    unsigned char localBytes[24];
    std::memcpy(localBytes, localSymbol, sizeof(localBytes));
    PrintBytes("local_bytes", localBytes, sizeof(localBytes));

    if (remoteBase == 0) {
        std::printf("cannot locate module in target\n");
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        std::printf("attach failed errno=%d\n", errno);
        return 1;
    }
    int status = 0;
    if (waitpid(pid, &status, __WALL) < 0) {
        std::printf("wait failed\n");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }

    unsigned char remoteBytes[24] = {0};
    const bool readOk = ReadProcessMemory(pid, remoteBase + offset, remoteBytes, sizeof(remoteBytes));
    std::printf("remote_read=%d\n", readOk ? 1 : 0);
    if (readOk) {
        PrintBytes("remote_bytes", remoteBytes, sizeof(remoteBytes));
        std::printf("bytes_equal=%d\n", std::memcmp(localBytes, remoteBytes, sizeof(localBytes)) == 0 ? 1 : 0);
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return 0;
}
