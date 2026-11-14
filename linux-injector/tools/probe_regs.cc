#define _GNU_SOURCE

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <pid>\n", argv[0]);
        return 2;
    }
    const pid_t pid = static_cast<pid_t>(std::atoi(argv[1]));
    if (pid <= 0) {
        return 2;
    }

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        std::printf("attach failed errno=%d\n", errno);
        return 1;
    }
    int status = 0;
    if (waitpid(pid, &status, __WALL) < 0) {
        std::printf("wait failed\n");
        return 1;
    }

#if defined(__x86_64__)
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) != 0) {
        std::printf("getregs failed errno=%d\n", errno);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }
    const unsigned long long original = regs.rip;
    std::printf("original rip=0x%llx rsp=0x%llx\n", original,
                static_cast<unsigned long long>(regs.rsp));

    const unsigned long long target = original + 0x1000;
    regs.rip = target;
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) != 0) {
        std::printf("setregs failed errno=%d\n", errno);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }

    struct user_regs_struct after;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &after) != 0) {
        std::printf("re-read failed errno=%d\n", errno);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return 1;
    }
    std::printf("wrote rip=0x%llx readback=0x%llx match=%d delta=%lld\n", target,
                static_cast<unsigned long long>(after.rip),
                static_cast<unsigned long long>(after.rip) == target ? 1 : 0,
                static_cast<long long>(after.rip) - static_cast<long long>(target));

    regs.rip = original;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    std::printf("restored and detached\n");
#else
    std::printf("x86_64 only probe\n");
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
#endif
    return 0;
}
