#include "core_elf.h"

#include "core.h"

#include <elf.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>

#include <cstdio>
#include <cstring>
#include <map>

namespace nexuslab_linux {

namespace {

#if defined(__aarch64__)
constexpr unsigned long long kRelativeRelocation = R_AARCH64_RELATIVE;
constexpr unsigned long long kAbsoluteRelocation = R_AARCH64_ABS64;
constexpr unsigned long long kGlobalDataRelocation = R_AARCH64_GLOB_DAT;
constexpr unsigned long long kJumpSlotRelocation = R_AARCH64_JUMP_SLOT;
#else
constexpr unsigned long long kRelativeRelocation = R_X86_64_RELATIVE;
constexpr unsigned long long kAbsoluteRelocation = R_X86_64_64;
constexpr unsigned long long kGlobalDataRelocation = R_X86_64_GLOB_DAT;
constexpr unsigned long long kJumpSlotRelocation = R_X86_64_JUMP_SLOT;
#endif

constexpr int kProtectionRead = 1;
constexpr int kProtectionWrite = 2;
constexpr int kProtectionExecute = 4;
constexpr int kMapPrivateAnonymous = 0x02 | 0x20;

struct LoadedSegment {
    unsigned long long virtualAddress;
    unsigned long long memorySize;
    unsigned long long fileOffset;
    unsigned long long fileSize;
    int protection;
};

struct SymbolTable {
    const char* stringTable;
    size_t stringTableSize;
    const Elf64_Sym* symbols;
    size_t symbolCount;
};

unsigned long long AlignDown(unsigned long long value, unsigned long long alignment) {
    return value & ~(alignment - 1);
}

unsigned long long AlignUp(unsigned long long value, unsigned long long alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

bool WaitForTargetStop(pid_t pid) {
    for (;;) {
        int status = 0;
        const pid_t waited = waitpid(pid, &status, __WALL);
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (WIFSTOPPED(status)) {
            return true;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            return false;
        }
    }
}

int ProtectionFromFlags(unsigned int flags) {
    int protection = 0;
    if ((flags & PF_R) != 0) {
        protection |= kProtectionRead;
    }
    if ((flags & PF_W) != 0) {
        protection |= kProtectionWrite;
    }
    if ((flags & PF_X) != 0) {
        protection |= kProtectionExecute;
    }
    return protection;
}

bool RemoteMmap(pid_t pid, unsigned long long length, int protection,
                unsigned long long* outAddress) {
    const unsigned long long mmapAddress = ResolveRemoteSymbol(pid, "mmap");
    if (mmapAddress == 0) {
        g_lastError = "cannot resolve mmap inside target";
        return false;
    }
    const std::vector<unsigned long long> arguments = {
        0,
        length,
        static_cast<unsigned long long>(protection),
        static_cast<unsigned long long>(kMapPrivateAnonymous),
        static_cast<unsigned long long>(-1LL),
        0,
    };
    unsigned long long result = 0;
    if (!CallRemoteFunction(pid, mmapAddress, arguments, &result)) {
        return false;
    }
    if (static_cast<long long>(result) < 0) {
        g_lastError = "mmap returned an error inside target";
        return false;
    }
    *outAddress = result;
    return true;
}

bool RemoteMprotect(pid_t pid, unsigned long long address, unsigned long long length,
                    int protection) {
    const unsigned long long mprotectAddress = ResolveRemoteSymbol(pid, "mprotect");
    if (mprotectAddress == 0) {
        g_lastError = "cannot resolve mprotect inside target";
        return false;
    }
    const std::vector<unsigned long long> arguments = {
        address,
        length,
        static_cast<unsigned long long>(protection),
    };
    unsigned long long result = 0;
    if (!CallRemoteFunction(pid, mprotectAddress, arguments, &result)) {
        return false;
    }
    if (result != 0) {
        g_lastError = "mprotect failed inside target";
        return false;
    }
    return true;
}

bool LocateDynamicSection(const std::vector<unsigned char>& image, const Elf64_Ehdr* header,
                          const Elf64_Phdr** outDynamic) {
    const Elf64_Phdr* segments = reinterpret_cast<const Elf64_Phdr*>(
        image.data() + header->e_phoff);
    for (size_t index = 0; index < header->e_phnum; ++index) {
        if (segments[index].p_type == PT_DYNAMIC) {
            *outDynamic = &segments[index];
            return true;
        }
    }
    return false;
}

}

std::vector<unsigned char> ReadLocalFile(const std::string& path) {
    std::vector<unsigned char> buffer;
    const int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return buffer;
    }
    unsigned char chunk[65536];
    for (;;) {
        const ssize_t readBytes = read(fd, chunk, sizeof(chunk));
        if (readBytes < 0) {
            buffer.clear();
            break;
        }
        if (readBytes == 0) {
            break;
        }
        buffer.insert(buffer.end(), chunk, chunk + readBytes);
    }
    close(fd);
    return buffer;
}


namespace {

struct DynamicInfo {
    const Elf64_Rela* relocationTable;
    size_t relocationCount;
    const Elf64_Rela* pltRelocationTable;
    size_t pltRelocationCount;
    const Elf64_Sym* symbolTable;
    size_t symbolCount;
    const char* stringTable;
    size_t stringTableSize;
    unsigned long long initArrayAddress;
    size_t initArrayCount;
    unsigned long long initAddress;
};

bool ParseDynamicInfo(const std::vector<unsigned char>& image, const Elf64_Phdr* dynamicSegment,
                      DynamicInfo* out) {
    std::memset(out, 0, sizeof(*out));

    const Elf64_Dyn* entries = reinterpret_cast<const Elf64_Dyn*>(
        image.data() + dynamicSegment->p_offset);
    const size_t maxEntries = dynamicSegment->p_filesz / sizeof(Elf64_Dyn);

    unsigned long long relaAddress = 0;
    unsigned long long relaSize = 0;
    unsigned long long jmprelAddress = 0;
    unsigned long long jmprelSize = 0;
    unsigned long long symtabAddress = 0;
    unsigned long long strtabAddress = 0;
    unsigned long long strtabSize = 0;
    unsigned long long pltRelocationKind = 0;

    for (size_t index = 0; index < maxEntries; ++index) {
        const Elf64_Dyn& entry = entries[index];
        if (entry.d_tag == DT_NULL) {
            break;
        }
        switch (entry.d_tag) {
            case DT_RELA:
                relaAddress = entry.d_un.d_ptr;
                break;
            case DT_RELASZ:
                relaSize = entry.d_un.d_val;
                break;
            case DT_JMPREL:
                jmprelAddress = entry.d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                jmprelSize = entry.d_un.d_val;
                break;
            case DT_PLTREL:
                pltRelocationKind = entry.d_un.d_val;
                break;
            case DT_SYMTAB:
                symtabAddress = entry.d_un.d_ptr;
                break;
            case DT_STRTAB:
                strtabAddress = entry.d_un.d_ptr;
                break;
            case DT_STRSZ:
                strtabSize = entry.d_un.d_val;
                break;
            case DT_INIT:
                out->initAddress = entry.d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                out->initArrayAddress = entry.d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                out->initArrayCount = entry.d_un.d_val / sizeof(unsigned long long);
                break;
            default:
                break;
        }
    }

    if (pltRelocationKind != DT_RELA && pltRelocationKind != 0) {
        g_lastError = "only RELA based PLT relocations are supported";
        return false;
    }

    out->relocationTable = reinterpret_cast<const Elf64_Rela*>(image.data() + relaAddress);
    out->relocationCount = relaSize / sizeof(Elf64_Rela);
    out->pltRelocationTable = reinterpret_cast<const Elf64_Rela*>(image.data() + jmprelAddress);
    out->pltRelocationCount = jmprelSize / sizeof(Elf64_Rela);
    out->symbolTable = reinterpret_cast<const Elf64_Sym*>(image.data() + symtabAddress);
    out->stringTable = reinterpret_cast<const char*>(image.data() + strtabAddress);
    out->stringTableSize = strtabSize;

    return true;
}

unsigned long long ResolveExternalSymbol(pid_t pid, const char* name) {
    return ResolveRemoteSymbol(pid, name);
}

}

bool ApplyRelocations(pid_t pid, const std::vector<unsigned char>& image, const DynamicInfo& info,
                      unsigned long long remoteBase, unsigned long long lowestAddress) {
    const unsigned long long remoteLoadOffset = remoteBase - lowestAddress;

    const size_t totalCount = info.relocationCount + info.pltRelocationCount;
    for (size_t index = 0; index < totalCount; ++index) {
        const bool isPlt = index >= info.relocationCount;
        const Elf64_Rela* table = isPlt ? info.pltRelocationTable : info.relocationTable;
        const Elf64_Rela& relocation = table[isPlt ? (index - info.relocationCount) : index];

        const unsigned long long type = ELF64_R_TYPE(relocation.r_info);
        const size_t symbolIndex = static_cast<size_t>(ELF64_R_SYM(relocation.r_info));
        const unsigned long long targetSlot = remoteLoadOffset + relocation.r_offset;

        if (type == kRelativeRelocation) {
            const unsigned long long value = remoteLoadOffset + relocation.r_addend;
            if (!WriteProcessMemory(pid, targetSlot, &value, sizeof(value))) {
                g_lastError = "cannot apply relative relocation";
                return false;
            }
            continue;
        }

        if (type != kAbsoluteRelocation && type != kGlobalDataRelocation &&
            type != kJumpSlotRelocation) {
            continue;
        }

        if (symbolIndex >= info.symbolCount && info.symbolCount != 0) {
            g_lastError = "relocation references an out of range symbol";
            return false;
        }

        const Elf64_Sym& symbol = info.symbolTable[symbolIndex];
        if (symbol.st_name >= info.stringTableSize) {
            g_lastError = "relocation symbol name is out of range";
            return false;
        }

        const char* symbolName = info.stringTable + symbol.st_name;
        if (symbolName[0] == 0) {
            continue;
        }

        unsigned long long resolved = ResolveExternalSymbol(pid, symbolName);
        if (resolved == 0) {
            g_lastError = std::string("cannot resolve imported symbol: ") + symbolName;
            return false;
        }

        const unsigned long long value = resolved + relocation.r_addend;
        if (!WriteProcessMemory(pid, targetSlot, &value, sizeof(value))) {
            g_lastError = std::string("cannot patch relocation for: ") + symbolName;
            return false;
        }
    }

    return true;
}

bool RunInitializers(pid_t pid, const DynamicInfo& info, unsigned long long remoteBase,
                     unsigned long long lowestAddress, unsigned long long* outEntryCount) {
    const unsigned long long remoteLoadOffset = remoteBase - lowestAddress;
    unsigned long long executed = 0;

    if (info.initArrayCount != 0 && info.initArrayAddress != 0) {
        const unsigned long long arrayAddress = remoteLoadOffset + info.initArrayAddress;
        std::vector<unsigned long long> entries(info.initArrayCount, 0);
        const size_t bytes = entries.size() * sizeof(unsigned long long);
        if (!ReadProcessMemory(pid, arrayAddress, entries.data(), bytes)) {
            g_lastError = "cannot read initializer array from target";
            return false;
        }

        for (unsigned long long entry : entries) {
            if (entry == 0) {
                continue;
            }
            const unsigned long long caller = remoteLoadOffset + entry;
            unsigned long long ignored = 0;
            if (!CallRemoteFunction(pid, caller, std::vector<unsigned long long>(), &ignored)) {
                g_lastError = std::string("initializer failed: ") + g_lastError;
                return false;
            }
            ++executed;
        }
    }

    if (info.initAddress != 0) {
        const unsigned long long caller = remoteLoadOffset + info.initAddress;
        unsigned long long ignored = 0;
        if (!CallRemoteFunction(pid, caller, std::vector<unsigned long long>(), &ignored)) {
            g_lastError = std::string("DT_INIT failed: ") + g_lastError;
            return false;
        }
        ++executed;
    }

    if (outEntryCount != nullptr) {
        *outEntryCount = executed;
    }
    return true;
}

bool MapElfImage(pid_t pid, const std::vector<unsigned char>& image, unsigned long long* outBase,
                 unsigned long long* outEntryCount) {
    if (image.size() < sizeof(Elf64_Ehdr)) {
        g_lastError = "library image is too small to be an ELF file";
        return false;
    }

    const Elf64_Ehdr* header = reinterpret_cast<const Elf64_Ehdr*>(image.data());
    if (std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        g_lastError = "library image is not a valid ELF file";
        return false;
    }
    if (header->e_ident[EI_CLASS] != ELFCLASS64) {
        g_lastError = "only 64-bit ELF images are supported";
        return false;
    }
    if (header->e_type != ET_DYN) {
        g_lastError = "only position independent libraries are supported";
        return false;
    }

    const Elf64_Phdr* segments = reinterpret_cast<const Elf64_Phdr*>(image.data() + header->e_phoff);

    std::vector<LoadedSegment> loadable;
    unsigned long long lowestAddress = ~0ULL;
    unsigned long long highestAddress = 0;
    const Elf64_Phdr* dynamicSegment = nullptr;

    for (size_t index = 0; index < header->e_phnum; ++index) {
        const Elf64_Phdr& segment = segments[index];
        if (segment.p_type == PT_DYNAMIC) {
            dynamicSegment = &segment;
            continue;
        }
        if (segment.p_type != PT_LOAD) {
            continue;
        }
        LoadedSegment entry;
        entry.virtualAddress = segment.p_vaddr;
        entry.memorySize = segment.p_memsz;
        entry.fileOffset = segment.p_offset;
        entry.fileSize = segment.p_filesz;
        entry.protection = ProtectionFromFlags(segment.p_flags);
        loadable.push_back(entry);

        const unsigned long long start = AlignDown(segment.p_vaddr, 0x1000);
        const unsigned long long end = AlignUp(segment.p_vaddr + segment.p_memsz, 0x1000);
        if (start < lowestAddress) {
            lowestAddress = start;
        }
        if (end > highestAddress) {
            highestAddress = end;
        }
    }

    if (loadable.empty()) {
        g_lastError = "library image has no loadable segments";
        return false;
    }

    const unsigned long long totalSize = highestAddress - lowestAddress;
    unsigned long long remoteBase = 0;
    if (!RemoteMmap(pid, totalSize, kProtectionRead | kProtectionWrite, &remoteBase)) {
        return false;
    }

    for (const LoadedSegment& entry : loadable) {
        if (entry.fileSize == 0) {
            continue;
        }
        if (entry.fileOffset + entry.fileSize > image.size()) {
            g_lastError = "library segment exceeds image size";
            return false;
        }
        const unsigned long long target = remoteBase + (entry.virtualAddress - lowestAddress);
        if (!WriteProcessMemory(pid, target, image.data() + entry.fileOffset, entry.fileSize)) {
            g_lastError = "cannot copy library segment into target";
            return false;
        }
    }

    if (dynamicSegment == nullptr) {
        g_lastError = "library image has no dynamic segment";
        return false;
    }

    DynamicInfo dynamicInfo;
    if (!ParseDynamicInfo(image, dynamicSegment, &dynamicInfo)) {
        return false;
    }

    dynamicInfo.symbolCount = dynamicInfo.stringTableSize;

    if (!ApplyRelocations(pid, image, dynamicInfo, remoteBase, lowestAddress)) {
        return false;
    }

    if (outBase != nullptr) {
        *outBase = remoteBase - lowestAddress;
    }

    unsigned long long initializers = 0;
    if (!RunInitializers(pid, dynamicInfo, remoteBase, lowestAddress, &initializers)) {
        return false;
    }

    if (outEntryCount != nullptr) {
        *outEntryCount = initializers;
    }

    return true;
}

bool InjectLibraryManual(pid_t pid, const std::string& libraryPath, unsigned long long* outBase,
                         unsigned long long* outInitializers) {
    const std::vector<unsigned char> image = ReadLocalFile(libraryPath);
    if (image.empty()) {
        g_lastError = "cannot read library file from disk: " + libraryPath;
        return false;
    }

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        g_lastError = "ptrace attach rejected (need matching uid or CAP_SYS_PTRACE)";
        return false;
    }

    if (!WaitForTargetStop(pid)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_lastError = "target did not stop after attach";
        return false;
    }

    unsigned long long mappedBase = 0;
    unsigned long long initializers = 0;
    const bool mapped = MapElfImage(pid, image, &mappedBase, &initializers);

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    if (!mapped) {
        return false;
    }

    if (outBase != nullptr) {
        *outBase = mappedBase;
    }
    if (outInitializers != nullptr) {
        *outInitializers = initializers;
    }
    return true;
}
}
