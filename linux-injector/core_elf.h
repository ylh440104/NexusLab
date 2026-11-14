#ifndef NEXUSLAB_LINUX_CORE_ELF_H
#define NEXUSLAB_LINUX_CORE_ELF_H

#include <sys/types.h>

#include <string>
#include <vector>

namespace nexuslab_linux {

bool MapElfImage(pid_t pid, const std::vector<unsigned char>& image, unsigned long long* outBase,
                 unsigned long long* outEntryCount);

bool InjectLibraryManual(pid_t pid, const std::string& libraryPath, unsigned long long* outBase,
                         unsigned long long* outInitializers);

std::vector<unsigned char> ReadLocalFile(const std::string& path);

}

#endif
