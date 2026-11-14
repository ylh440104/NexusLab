#include "core.h"

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace nexuslab_linux {
namespace {

std::string ReadCommFile(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/comm", static_cast<int>(pid));
    FILE* fp = std::fopen(path, "r");
    if (fp == nullptr) {
        return std::string();
    }
    char buffer[256] = {0};
    if (std::fgets(buffer, sizeof(buffer), fp) == nullptr) {
        std::fclose(fp);
        return std::string();
    }
    std::fclose(fp);
    size_t length = std::strlen(buffer);
    while (length > 0) {
        char tail = buffer[length - 1];
        if (tail != '\n' && tail != '\r') {
            break;
        }
        buffer[--length] = 0;
    }
    return std::string(buffer);
}

pid_t ReadParentPid(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/stat", static_cast<int>(pid));
    FILE* fp = std::fopen(path, "r");
    if (fp == nullptr) {
        return -1;
    }
    char buffer[512] = {0};
    size_t read = std::fread(buffer, 1, sizeof(buffer) - 1, fp);
    std::fclose(fp);
    buffer[read] = 0;
    char* closing = std::strrchr(buffer, ')');
    if (closing == nullptr) {
        return -1;
    }
    return static_cast<pid_t>(std::atoi(closing + 2));
}

bool IsTargetComm(const std::string& comm) {
    return comm == "qq" || comm == "QQ";
}

}

std::vector<ProcessEntry> ListProcesses() {
    std::vector<ProcessEntry> entries;
    DIR* procDir = opendir("/proc");
    if (procDir == nullptr) {
        return entries;
    }
    while (struct dirent* item = readdir(procDir)) {
        if (item->d_name[0] < '0' || item->d_name[0] > '9') {
            continue;
        }
        pid_t pid = static_cast<pid_t>(std::atoi(item->d_name));
        if (pid <= 0) {
            continue;
        }
        ProcessEntry entry;
        entry.pid = pid;
        entry.comm = ReadCommFile(pid);
        entries.push_back(entry);
    }
    closedir(procDir);
    return entries;
}

std::vector<pid_t> FindMainProcesses() {
    std::vector<ProcessEntry> candidates;
    for (const ProcessEntry& entry : ListProcesses()) {
        if (IsTargetComm(entry.comm)) {
            candidates.push_back(entry);
        }
    }

    std::vector<pid_t> children;
    for (const ProcessEntry& entry : candidates) {
        pid_t parent = ReadParentPid(entry.pid);
        if (parent > 1) {
            children.push_back(parent);
        }
    }

    std::vector<pid_t> mains;
    for (const ProcessEntry& entry : candidates) {
        bool hasTargetChild = false;
        for (ProcessEntry& other : candidates) {
            if (other.pid == entry.pid) {
                continue;
            }
            if (ReadParentPid(other.pid) == entry.pid) {
                hasTargetChild = true;
                break;
            }
        }
        if (hasTargetChild) {
            continue;
        }
        bool referencedAsParent = false;
        for (pid_t parent : children) {
            if (parent == entry.pid) {
                referencedAsParent = true;
                break;
            }
        }
        if (!referencedAsParent) {
            mains.push_back(entry.pid);
        }
    }

    if (!mains.empty()) {
        return mains;
    }

    for (const ProcessEntry& entry : candidates) {
        if (ReadParentPid(entry.pid) <= 1) {
            mains.push_back(entry.pid);
        }
    }
    return mains;
}

std::vector<FileHolder> QueryFileHolders(const std::string& targetPath) {
    std::vector<FileHolder> holders;
    char resolved[PATH_MAX] = {0};
    if (realpath(targetPath.c_str(), resolved) == nullptr) {
        std::snprintf(resolved, sizeof(resolved), "%s", targetPath.c_str());
    }

    for (const ProcessEntry& entry : ListProcesses()) {
        char fdPath[64];
        std::snprintf(fdPath, sizeof(fdPath), "/proc/%d/fd", static_cast<int>(entry.pid));
        DIR* fdDir = opendir(fdPath);
        if (fdDir == nullptr) {
            continue;
        }
        bool alreadyRecorded = false;
        while (struct dirent* item = readdir(fdDir)) {
            if (alreadyRecorded) {
                break;
            }
            if (item->d_name[0] < '0' || item->d_name[0] > '9') {
                continue;
            }
            char linkPath[128];
            std::snprintf(linkPath, sizeof(linkPath), "/proc/%d/fd/%s",
                          static_cast<int>(entry.pid), item->d_name);
            char linkTarget[PATH_MAX] = {0};
            ssize_t length = readlink(linkPath, linkTarget, sizeof(linkTarget) - 1);
            if (length <= 0) {
                continue;
            }
            linkTarget[length] = 0;
            if (std::strcmp(linkTarget, resolved) == 0) {
                FileHolder holder;
                holder.pid = entry.pid;
                holder.name = entry.comm;
                holders.push_back(holder);
                alreadyRecorded = true;
            }
        }
        closedir(fdDir);
    }
    return holders;
}

bool ReadProcessMemory(pid_t pid, unsigned long long address, void* buffer, size_t length) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/mem", static_cast<int>(pid));
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    ssize_t readBytes = pread(fd, buffer, length, static_cast<off_t>(address));
    close(fd);
    return readBytes == static_cast<ssize_t>(length);
}

bool WriteProcessMemory(pid_t pid, unsigned long long address, const void* buffer, size_t length) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/mem", static_cast<int>(pid));
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return false;
    }
    ssize_t written = pwrite(fd, buffer, length, static_cast<off_t>(address));
    close(fd);
    return written == static_cast<ssize_t>(length);
}

unsigned long long FindModuleBase(pid_t pid, const char* soname) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", static_cast<int>(pid));
    FILE* fp = std::fopen(path, "r");
    if (fp == nullptr) {
        return 0;
    }
    char line[1024];
    unsigned long long lowest = 0;
    while (std::fgets(line, sizeof(line), fp) != nullptr) {
        if (std::strstr(line, soname) == nullptr) {
            continue;
        }
        bool readable = std::strstr(line, " r-xp ") != nullptr ||
                        std::strstr(line, " r--p ") != nullptr;
        if (!readable) {
            continue;
        }
        unsigned long long start = std::strtoull(line, nullptr, 16);
        if (start == 0) {
            continue;
        }
        if (lowest == 0 || start < lowest) {
            lowest = start;
        }
    }
    std::fclose(fp);
    return lowest;
}

unsigned long long ResolveRemoteSymbol(pid_t pid, const char* symbol) {
    void* localAddress = dlsym(RTLD_DEFAULT, symbol);
    if (localAddress == nullptr) {
        return 0;
    }
    Dl_info info;
    if (dladdr(localAddress, &info) == 0 || info.dli_fbase == nullptr || info.dli_fname == nullptr) {
        return 0;
    }
    unsigned long long localBase = reinterpret_cast<unsigned long long>(info.dli_fbase);
    unsigned long long offset = reinterpret_cast<unsigned long long>(localAddress) - localBase;

    unsigned long long remoteBase = FindModuleBase(pid, info.dli_fname);
    if (remoteBase == 0) {
        const char* slash = std::strrchr(info.dli_fname, '/');
        if (slash != nullptr) {
            remoteBase = FindModuleBase(pid, slash + 1);
        }
    }
    if (remoteBase == 0) {
        return 0;
    }
    return remoteBase + offset;
}

}
