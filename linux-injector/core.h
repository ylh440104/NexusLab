#ifndef NEXUSLAB_LINUX_CORE_H
#define NEXUSLAB_LINUX_CORE_H

#include <sys/types.h>

#include <string>
#include <vector>

namespace nexuslab_linux {

struct ProcessEntry {
    pid_t pid;
    std::string comm;
};

struct FileHolder {
    pid_t pid;
    std::string name;
};

extern std::string g_lastError;

std::vector<ProcessEntry> ListProcesses();

std::vector<pid_t> FindMainProcesses();

std::vector<FileHolder> QueryFileHolders(const std::string& targetPath);

bool ReadProcessMemory(pid_t pid, unsigned long address, void* buffer, size_t length);

bool WriteProcessMemory(pid_t pid, unsigned long address, const void* buffer, size_t length);

unsigned long FindModuleBase(pid_t pid, const char* soname);

unsigned long ResolveRemoteSymbol(pid_t pid, const char* symbol);

bool CallRemoteFunction(pid_t pid, unsigned long address, const std::vector<unsigned long>& args,
                        unsigned long* outReturn);

bool InjectLibrary(pid_t pid, const std::string& libraryPath, unsigned long* outHandle,
                   unsigned long* outBase);

}

#endif
