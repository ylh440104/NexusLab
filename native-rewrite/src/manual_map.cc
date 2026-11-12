#include "manual_map.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace mmap {
namespace {

const uint32_t kMaxRemoteAttempts = 8;
const size_t kWriteChunk = 0x1000;

struct ParsedImage {
    std::vector<uint8_t> buffer;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    uint64_t imageBase;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t entryRva;
    uint32_t exceptionDirRva;
    uint32_t relocDirRva;
    uint32_t relocDirSize;
    uint32_t importDirRva;
    uint32_t tlsDirRva;
    uint32_t sectionAlignment;
};


std::string LastErrorText(DWORD code) {
    return "win32 error " + std::to_string(static_cast<unsigned long>(code));
}

PIMAGE_SECTION_HEADER SectionHeader(ParsedImage& image, uint32_t index) {
    return IMAGE_FIRST_SECTION(image.nt) + index;
}

bool RvaInSection(PIMAGE_SECTION_HEADER section, uint32_t rva, uint32_t length) {
    uint32_t start = section->VirtualAddress;
    uint32_t span = std::max<uint32_t>(section->Misc.VirtualSize, section->SizeOfRawData);
    if (span == 0) {
        return false;
    }
    return rva >= start && rva + length <= start + span;
}

uint8_t* ResolveRva(ParsedImage& image, uint32_t rva, uint32_t length) {
    for (WORD i = 0; i < image.nt->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER section = SectionHeader(image, i);
        if (!RvaInSection(section, rva, length)) {
            continue;
        }
        uint32_t delta = rva - section->VirtualAddress;
        if (delta + length > section->SizeOfRawData) {
            return nullptr;
        }
        uint64_t offset = static_cast<uint64_t>(section->PointerToRawData) + delta;
        if (offset + length > image.buffer.size()) {
            return nullptr;
        }
        return image.buffer.data() + offset;
    }
    if (rva + length <= image.sizeOfHeaders && rva + length <= image.buffer.size()) {
        return image.buffer.data() + rva;
    }
    return nullptr;
}

uint32_t FindExportRva(ParsedImage& image, const char* name) {
    auto& dir = image.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return 0;
    }
    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        ResolveRva(image, dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)));
    if (exports == nullptr) {
        return 0;
    }
    auto names = reinterpret_cast<DWORD*>(
        ResolveRva(image, exports->AddressOfNames, exports->NumberOfNames * sizeof(DWORD)));
    auto functions = reinterpret_cast<DWORD*>(
        ResolveRva(image, exports->AddressOfFunctions, exports->NumberOfFunctions * sizeof(DWORD)));
    if (names == nullptr || functions == nullptr) {
        return 0;
    }
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* candidate = reinterpret_cast<const char*>(
            ResolveRva(image, names[i], 1));
        if (candidate == nullptr) {
            continue;
        }
        if (std::strcmp(candidate, name) != 0) {
            continue;
        }
        auto ordinals = reinterpret_cast<WORD*>(
            ResolveRva(image, exports->AddressOfNameOrdinals, exports->NumberOfNames * sizeof(WORD)));
        if (ordinals == nullptr) {
            return 0;
        }
        WORD ordinal = ordinals[i];
        if (ordinal >= exports->NumberOfFunctions) {
            return 0;
        }
        return functions[ordinal];
    }
    return 0;
}

bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out, std::string& error,
                   DWORD& code) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        code = GetLastError();
        error = "CreateFileW failed: " + LastErrorText(code);
        return false;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(file, &size)) {
        code = GetLastError();
        error = "GetFileSizeEx failed";
        CloseHandle(file);
        return false;
    }
    if (size.QuadPart <= 0 || size.QuadPart > (64LL * 1024 * 1024)) {
        error = "dll size out of range";
        CloseHandle(file);
        return false;
    }
    out.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read != out.size()) {
        code = GetLastError();
        error = "ReadFile failed";
        return false;
    }
    return true;
}

bool ValidateImage(const std::vector<uint8_t>& buffer, ParsedImage& image, std::string& error) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        error = "file too small for dos header";
        return false;
    }
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<uint8_t*>(buffer.data()));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error = "invalid dos signature";
        return false;
    }
    if (dos->e_lfanew < 0 ||
        static_cast<uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buffer.size()) {
        error = "invalid pe offset";
        return false;
    }
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(const_cast<uint8_t*>(buffer.data()) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        error = "invalid nt signature";
        return false;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        error = "target dll is not amd64";
        return false;
    }
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
        error = "target is not a dll";
        return false;
    }
    if (nt->OptionalHeader.SizeOfImage == 0 ||
        nt->OptionalHeader.SizeOfImage > (256u * 1024u * 1024u)) {
        error = "invalid image size";
        return false;
    }

    image.buffer = buffer;
    image.dos = dos;
    image.nt = nt;
    image.imageBase = nt->OptionalHeader.ImageBase;
    image.sizeOfImage = nt->OptionalHeader.SizeOfImage;
    image.sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    image.entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    image.sectionAlignment = nt->OptionalHeader.SectionAlignment;

    auto& dirs = nt->OptionalHeader.DataDirectory;
    image.exceptionDirRva = dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    image.relocDirRva = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    image.relocDirSize = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    image.importDirRva = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    image.tlsDirRva = dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    return true;
}

bool MapSections(ParsedImage& image, uint8_t* local, std::string& error) {
    if (image.sizeOfHeaders > image.sizeOfImage) {
        error = "header size exceeds image size";
        return false;
    }
    memcpy(local, image.buffer.data(), std::min<size_t>(image.sizeOfHeaders, image.buffer.size()));
    for (WORD i = 0; i < image.nt->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER section = SectionHeader(image, i);
        if (section->SizeOfRawData == 0) {
            continue;
        }
        uint64_t rawEnd = static_cast<uint64_t>(section->PointerToRawData) + section->SizeOfRawData;
        if (rawEnd > image.buffer.size()) {
            error = "section raw data out of bounds";
            return false;
        }
        uint64_t virtualEnd = static_cast<uint64_t>(section->VirtualAddress) + section->SizeOfRawData;
        if (virtualEnd > image.sizeOfImage) {
            error = "section virtual range out of bounds";
            return false;
        }
        memcpy(local + section->VirtualAddress,
               image.buffer.data() + section->PointerToRawData,
               section->SizeOfRawData);
    }
    return true;
}

void ApplyRelocations(ParsedImage& image, uint8_t* local, uint64_t delta) {
    if (image.relocDirRva == 0 || image.relocDirSize == 0 || delta == 0) {
        return;
    }
    uint8_t* cursor = ResolveRva(image, image.relocDirRva, image.relocDirSize);
    if (cursor == nullptr) {
        return;
    }
    uint8_t* end = cursor + image.relocDirSize;
    while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= end) {
        auto block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(cursor);
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            break;
        }
        if (cursor + block->SizeOfBlock > end) {
            break;
        }
        uint32_t entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto entries = reinterpret_cast<PWORD>(cursor + sizeof(IMAGE_BASE_RELOCATION));
        for (uint32_t i = 0; i < entryCount; ++i) {
            WORD entry = entries[i];
            WORD type = static_cast<WORD>((entry >> 12) & 0xF);
            WORD offset = static_cast<WORD>(entry & 0x0FFF);
            uint64_t target = static_cast<uint64_t>(block->VirtualAddress) + offset;
            if (target + sizeof(uint64_t) > image.sizeOfImage) {
                continue;
            }
            if (type == IMAGE_REL_BASED_DIR64) {
                auto slot = reinterpret_cast<uint64_t*>(local + target);
                *slot = *slot + delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                auto slot32 = reinterpret_cast<uint32_t*>(local + target);
                *slot32 = *slot32 + static_cast<uint32_t>(delta);
            }
        }
        cursor += block->SizeOfBlock;
    }
}

bool ResolveImports(ParsedImage& image, uint8_t* local, std::string& error) {
    if (image.importDirRva == 0) {
        return true;
    }
    uint8_t* cursor = ResolveRva(image, image.importDirRva, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (cursor == nullptr) {
        error = "import directory not resolvable";
        return false;
    }
    for (;;) {
        auto descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(cursor);
        if (descriptor->Name == 0) {
            break;
        }
        uint8_t* namePtr = ResolveRva(image, descriptor->Name, 1);
        if (namePtr == nullptr) {
            error = "import module name not resolvable";
            return false;
        }
        HMODULE module = LoadLibraryA(reinterpret_cast<const char*>(namePtr));
        if (module == nullptr) {
            error = std::string("LoadLibraryA failed for ") + reinterpret_cast<const char*>(namePtr);
            return false;
        }
        uint32_t thunkRva = descriptor->OriginalFirstThunk != 0 ? descriptor->OriginalFirstThunk
                                                                : descriptor->FirstThunk;
        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
            ResolveRva(image, thunkRva, sizeof(IMAGE_THUNK_DATA64)));
        auto iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(
            ResolveRva(image, descriptor->FirstThunk, sizeof(IMAGE_THUNK_DATA64)));
        if (thunk == nullptr || iat == nullptr) {
            error = "import thunk not resolvable";
            return false;
        }
        while (thunk->u1.AddressOfData != 0) {
            FARPROC resolved = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                WORD ordinal = static_cast<WORD>(IMAGE_ORDINAL64(thunk->u1.Ordinal));
                resolved = GetProcAddress(module, reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(ordinal)));
            } else {
                auto byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                    ResolveRva(image, static_cast<uint32_t>(thunk->u1.AddressOfData), sizeof(WORD)));
                if (byName != nullptr) {
                    resolved = GetProcAddress(module, reinterpret_cast<LPCSTR>(byName->Name));
                }
            }
            if (resolved == nullptr) {
                error = "GetProcAddress failed during import resolution";
                return false;
            }
            iat->u1.Function = reinterpret_cast<uint64_t>(resolved);
            ++thunk;
            ++iat;
        }
        ++descriptor;
        cursor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return true;
}

bool WriteRemoteChunked(HANDLE process, uint64_t address, const uint8_t* data, size_t size,
                        std::string& error) {
    size_t offset = 0;
    while (offset < size) {
        size_t remaining = size - offset;
        size_t chunk = remaining < kWriteChunk ? remaining : kWriteChunk;
        SIZE_T written = 0;
        if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(address + offset),
                                data + offset, chunk, &written) || written != chunk) {
            error = "WriteProcessMemory failed at offset " + std::to_string(offset) + ": " +
                    LastErrorText(GetLastError());
            return false;
        }
        offset += chunk;
    }
    return true;
}

uint32_t ProtectionForSection(uint32_t characteristics) {
    bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (executable && writable) {
        return PAGE_EXECUTE_READWRITE;
    }
    if (executable) {
        return readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    }
    if (writable) {
        return PAGE_READWRITE;
    }
    return readable ? PAGE_READONLY : PAGE_NOACCESS;
}

bool AllocateImage(HANDLE process, uint32_t size, uint64_t preferred, uint32_t alignment,
                   uint64_t& base, std::string& error) {
    uint32_t step = alignment == 0 ? 0x10000 : alignment;
    for (uint32_t attempt = 0; attempt < kMaxRemoteAttempts; ++attempt) {
        uint64_t hint = preferred + static_cast<uint64_t>(attempt) * step;
        void* remote = VirtualAllocEx(process, reinterpret_cast<LPVOID>(hint), size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (remote != nullptr) {
            base = reinterpret_cast<uint64_t>(remote);
            return true;
        }
    }
    void* remote = VirtualAllocEx(process, nullptr, size, MEM_RESERVE | MEM_COMMIT,
                                  PAGE_EXECUTE_READWRITE);
    if (remote != nullptr) {
        base = reinterpret_cast<uint64_t>(remote);
        return true;
    }
    error = "VirtualAllocEx failed: " + LastErrorText(GetLastError());
    return false;
}

bool ProtectSections(HANDLE process, ParsedImage& image, uint64_t base, std::string& error) {
    DWORD old = 0;
    uint32_t headerSpan = std::min<uint32_t>(image.sizeOfHeaders, image.sizeOfImage);
    if (headerSpan > 0) {
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(base), headerSpan,
                              PAGE_READONLY, &old)) {
            error = "VirtualProtectEx headers failed: " + LastErrorText(GetLastError());
            return false;
        }
    }
    for (WORD i = 0; i < image.nt->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER section = SectionHeader(image, i);
        uint32_t span = std::max<uint32_t>(section->Misc.VirtualSize, section->SizeOfRawData);
        if (span == 0) {
            continue;
        }
        uint64_t start = base + section->VirtualAddress;
        if (start + span > base + image.sizeOfImage) {
            span = static_cast<uint32_t>(base + image.sizeOfImage - start);
        }
        if (span == 0) {
            continue;
        }
        uint32_t protection = ProtectionForSection(section->Characteristics);
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(start), span, protection, &old)) {
            error = "VirtualProtectEx section failed: " + LastErrorText(GetLastError());
            return false;
        }
    }
    return true;
}


struct NativeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct NativeListEntry {
    NativeListEntry* Flink;
    NativeListEntry* Blink;
};

struct NativeLdrEntry {
    NativeListEntry InLoadOrderLinks;
    NativeListEntry InMemoryOrderLinks;
    NativeListEntry InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    NativeUnicodeString FullDllName;
    NativeUnicodeString BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    NativeListEntry HashLinks;
    ULONG TimeDateStamp;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    NativeListEntry ForwarderLinks;
    NativeListEntry ServiceTagLinks;
    NativeListEntry StaticLinks;
    PVOID ContextInformation;
    ULONG64 OriginalBase;
    LARGE_INTEGER LoadTime;
};

struct NativePebLdrData {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    NativeListEntry InLoadOrderModuleList;
    NativeListEntry InMemoryOrderModuleList;
    NativeListEntry InInitializationOrderModuleList;
};

struct NativePeb {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    NativePebLdrData* Ldr;
};

#pragma pack(push, 1)
struct RemoteCall {
    uint64_t entryPoint;
    uint64_t imageBase;
    uint64_t sizeOfImage;
    uint64_t ldrpHandleTlsData;
    uint64_t rtlAddFunctionTable;
    uint64_t exceptionTable;
    uint32_t exceptionEntryCount;
    uint32_t hasTls;
    uint64_t moduleNameChars;
    uint32_t moduleNameLength;
    uint32_t resultCode;
    uint64_t entryStorage;
    uint64_t reserved;
};
#pragma pack(pop)

const size_t kRemoteCallNameCapacity = 260;

typedef DWORD(WINAPI* RemoteEntryFn)(void* parameter);
typedef BOOL(WINAPI* DllMainFn)(void* module, DWORD reason, void* reserved);
typedef NTSTATUS(NTAPI* LdrpHandleTlsDataFn)(void* entry);
typedef BOOLEAN(NTAPI* RtlAddFunctionTableFn)(void* table, uint32_t count, uint64_t base);

DWORD WINAPI RemoteEntry(void* parameter) {
    RemoteCall* call = static_cast<RemoteCall*>(parameter);
    if (call == nullptr) {
        return 0;
    }

    call->resultCode = 0x1000;

    if (call->entryPoint == 0) {
        call->resultCode = 0x1001;
        return 0;
    }

    NativePeb* peb = reinterpret_cast<NativePeb*>(__readgsqword(0x60));
    if (peb == nullptr || peb->Ldr == nullptr) {
        call->resultCode = 0x1002;
        return 0;
    }

    call->resultCode = 0x2000;

    NativeListEntry* head = &peb->Ldr->InLoadOrderModuleList;
    NativeLdrEntry* template_entry = reinterpret_cast<NativeLdrEntry*>(head->Flink);

    call->resultCode = 0x3000;

    NativeLdrEntry* new_entry = reinterpret_cast<NativeLdrEntry*>(call->entryStorage);
    if (new_entry == nullptr) {
        call->resultCode = 0x3001;
        return 0;
    }

    call->resultCode = 0x4000;

    *new_entry = *template_entry;
    new_entry->DllBase = reinterpret_cast<PVOID>(call->imageBase);
    new_entry->SizeOfImage = static_cast<ULONG>(call->sizeOfImage);
    new_entry->EntryPoint = nullptr;
    new_entry->Flags |= 0x00000004;

    wchar_t* name_buffer = reinterpret_cast<wchar_t*>(call->moduleNameChars);
    USHORT name_bytes = static_cast<USHORT>(call->moduleNameLength * sizeof(wchar_t));

    new_entry->FullDllName.Length = name_bytes;
    new_entry->FullDllName.MaximumLength = static_cast<USHORT>(name_bytes + sizeof(wchar_t));
    new_entry->FullDllName.Buffer = name_buffer;
    new_entry->BaseDllName.Length = name_bytes;
    new_entry->BaseDllName.MaximumLength = static_cast<USHORT>(name_bytes + sizeof(wchar_t));
    new_entry->BaseDllName.Buffer = name_buffer;

    new_entry->InLoadOrderLinks.Flink = &new_entry->InLoadOrderLinks;
    new_entry->InLoadOrderLinks.Blink = &new_entry->InLoadOrderLinks;
    new_entry->InMemoryOrderLinks.Flink = &new_entry->InMemoryOrderLinks;
    new_entry->InMemoryOrderLinks.Blink = &new_entry->InMemoryOrderLinks;
    new_entry->InInitializationOrderLinks.Flink = &new_entry->InInitializationOrderLinks;
    new_entry->InInitializationOrderLinks.Blink = &new_entry->InInitializationOrderLinks;

    NativeListEntry* in_load_tail = head->Blink;
    new_entry->InLoadOrderLinks.Flink = head;
    new_entry->InLoadOrderLinks.Blink = in_load_tail;
    in_load_tail->Flink = &new_entry->InLoadOrderLinks;
    head->Blink = &new_entry->InLoadOrderLinks;

    NativeListEntry* in_memory_head = &peb->Ldr->InMemoryOrderModuleList;
    NativeListEntry* in_memory_tail = in_memory_head->Blink;
    new_entry->InMemoryOrderLinks.Flink = in_memory_head;
    new_entry->InMemoryOrderLinks.Blink = in_memory_tail;
    in_memory_tail->Flink = &new_entry->InMemoryOrderLinks;
    in_memory_head->Blink = &new_entry->InMemoryOrderLinks;

    call->resultCode = 0x5000;

    if (call->hasTls != 0 && call->ldrpHandleTlsData != 0) {
        LdrpHandleTlsDataFn handle_tls =
            reinterpret_cast<LdrpHandleTlsDataFn>(call->ldrpHandleTlsData);
        handle_tls(new_entry);
    }

    call->resultCode = 0x6000;

    if (call->exceptionTable != 0 && call->exceptionEntryCount != 0 &&
        call->rtlAddFunctionTable != 0 && call->reserved != 0) {
        RtlAddFunctionTableFn add_table =
            reinterpret_cast<RtlAddFunctionTableFn>(call->rtlAddFunctionTable);
        add_table(reinterpret_cast<void*>(call->exceptionTable),
                  call->exceptionEntryCount, call->imageBase);
    }

    call->resultCode = 0x7000;

    DllMainFn dll_main = reinterpret_cast<DllMainFn>(call->entryPoint);
    BOOL loaded = dll_main(reinterpret_cast<void*>(call->imageBase), 1, nullptr);
    call->resultCode = loaded != FALSE ? 0x8000 : 0x8001;
    return 0;
}

DWORD WINAPI RemoteEntryEnd(void* parameter) {
    (void)parameter;
    return 0;
}

bool RunRemoteCall(HANDLE process, uint64_t functionAddress, uint64_t parameterAddress,
                   DWORD timeoutMs, DWORD& exitCode, std::string& error) {
    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(functionAddress),
                                       reinterpret_cast<LPVOID>(parameterAddress), 0, nullptr);
    if (thread == nullptr) {
        error = "CreateRemoteThread failed: " + LastErrorText(GetLastError());
        return false;
    }
    DWORD wait = WaitForSingleObject(thread, timeoutMs);
    if (wait != WAIT_OBJECT_0) {
        CloseHandle(thread);
        error = "remote thread did not finish";
        return false;
    }
    DWORD code = 0;
    GetExitCodeThread(thread, &code);
    CloseHandle(thread);
    exitCode = code;
    return true;
}

bool ResolveNtdllRva(const char* name, uint32_t& rva) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return false;
    }
    FARPROC local = GetProcAddress(ntdll, name);
    if (local == nullptr) {
        return false;
    }
    uint64_t base = reinterpret_cast<uint64_t>(ntdll);
    uint64_t target = reinterpret_cast<uint64_t>(local);
    if (target < base) {
        return false;
    }
    rva = static_cast<uint32_t>(target - base);
    return true;
}

uint32_t CountExceptionEntries(ParsedImage& image) {
    if (image.exceptionDirRva == 0) {
        return 0;
    }
    uint32_t size = image.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (size < 12) {
        return 0;
    }
    return size / 12;
}

}

Result Inject(DWORD pid, const std::wstring& dllPath) {
    Result result;
    result.ok = false;
    result.lastError = 0;
    result.handle = Handle{0, 0, 0, 0, 0};

    if (pid == 0) {
        result.error = "pid is zero";
        return result;
    }

    std::vector<uint8_t> raw;
    std::string readError;
    DWORD readCode = 0;
    if (!ReadFileBytes(dllPath, raw, readError, readCode)) {
        result.error = readError;
        result.lastError = readCode;
        return result;
    }

    ParsedImage image;
    std::string parseError;
    if (!ValidateImage(raw, image, parseError)) {
        result.error = parseError;
        return result;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == nullptr) {
        DWORD openCode = GetLastError();
        process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
                              FALSE, pid);
        if (process == nullptr) {
            result.error = "OpenProcess failed: " + LastErrorText(openCode);
            result.lastError = openCode;
            return result;
        }
    }

    uint64_t base = 0;
    std::string allocError;
    if (!AllocateImage(process, image.sizeOfImage, image.imageBase, image.sectionAlignment,
                       base, allocError)) {
        DWORD allocCode = GetLastError();
        CloseHandle(process);
        result.error = allocError;
        result.lastError = allocCode;
        return result;
    }

    std::vector<uint8_t> local(image.sizeOfImage, 0);
    std::string mapError;
    if (!MapSections(image, local.data(), mapError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = mapError;
        return result;
    }

    ApplyRelocations(image, local.data(), base - image.imageBase);

    if (!ResolveImports(image, local.data(), mapError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = mapError;
        return result;
    }

    if (!WriteRemoteChunked(process, base, local.data(), local.size(), mapError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = mapError;
        return result;
    }

    uint64_t entry = base + image.entryRva;
    uint64_t exceptionTable = image.exceptionDirRva != 0 ? base + image.exceptionDirRva : 0;
    uint32_t exceptionCount = CountExceptionEntries(image);

    uint32_t tlsRva = 0;
    uint64_t ldrpHandleTlsData = 0;
    if (image.tlsDirRva != 0 && ResolveNtdllRva("LdrpHandleTlsData", tlsRva)) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll != nullptr) {
            ldrpHandleTlsData =
                reinterpret_cast<uint64_t>(ntdll) + static_cast<uint64_t>(tlsRva);
        }
    }

    uint64_t rtlAddFunctionTable = 0;
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll != nullptr) {
            FARPROC fn = GetProcAddress(ntdll, "RtlAddFunctionTable");
            rtlAddFunctionTable = reinterpret_cast<uint64_t>(fn);
        }
    }

    std::wstring baseName = dllPath;
    size_t slash = baseName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        baseName = baseName.substr(slash + 1);
    }
    if (baseName.size() > 200) {
        baseName = baseName.substr(0, 200);
    }

    uint64_t remoteEntrySize = reinterpret_cast<uint64_t>(&RemoteEntryEnd) -
                               reinterpret_cast<uint64_t>(&RemoteEntry);

    void* scratch = VirtualAllocEx(process, nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT,
                                   PAGE_EXECUTE_READWRITE);
    if (scratch == nullptr) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = "remote scratch alloc failed: " + LastErrorText(GetLastError());
        return result;
    }
    uint64_t scratchAddress = reinterpret_cast<uint64_t>(scratch);
    uint64_t remoteEntryAddress = scratchAddress;
    uint64_t remoteCallAddress = scratchAddress + 0x1000;
    uint64_t remoteNameAddress = scratchAddress + 0x1000 - kRemoteCallNameCapacity * sizeof(wchar_t);

    std::string writeError;
    if (!WriteRemoteChunked(process, remoteEntryAddress,
                            reinterpret_cast<const uint8_t*>(&RemoteEntry),
                            static_cast<size_t>(remoteEntrySize), writeError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = writeError;
        return result;
    }

    RemoteCall call;
    memset(&call, 0, sizeof(call));
    call.entryPoint = entry;
    call.imageBase = base;
    call.sizeOfImage = image.sizeOfImage;
    call.ldrpHandleTlsData = ldrpHandleTlsData;
    call.rtlAddFunctionTable = rtlAddFunctionTable;
    call.exceptionTable = exceptionTable;
    call.exceptionEntryCount = exceptionCount;
    call.hasTls = image.tlsDirRva != 0 ? 1 : 0;
    call.moduleNameChars = remoteNameAddress;
    call.moduleNameLength = static_cast<uint32_t>(baseName.size());
    call.resultCode = 0;

    void* entryStorage = VirtualAllocEx(process, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT,
                                        PAGE_READWRITE);
    if (entryStorage == nullptr) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = "entry storage alloc failed: " + LastErrorText(GetLastError());
        return result;
    }
    call.entryStorage = reinterpret_cast<uint64_t>(entryStorage);
    call.reserved = 0;

    if (!WriteRemoteChunked(process, remoteNameAddress,
                            reinterpret_cast<const uint8_t*>(baseName.c_str()),
                            baseName.size() * sizeof(wchar_t), writeError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = writeError;
        return result;
    }

    if (!WriteRemoteChunked(process, remoteCallAddress,
                            reinterpret_cast<const uint8_t*>(&call), sizeof(call),
                            writeError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = writeError;
        return result;
    }

    std::string protError;
    if (!ProtectSections(process, image, base, protError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = protError;
        return result;
    }

    std::string threadError;
    DWORD exitCode = 0;
    if (!RunRemoteCall(process, remoteEntryAddress, remoteCallAddress, 30000, exitCode,
                       threadError)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = threadError;
        return result;
    }

    RemoteCall outcome;
    memset(&outcome, 0, sizeof(outcome));
    SIZE_T readBack = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPVOID>(remoteCallAddress), &outcome,
                           sizeof(outcome), &readBack) || readBack != sizeof(outcome)) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = "failed to read remote result: " + LastErrorText(GetLastError());
        return result;
    }

    VirtualFreeEx(process, reinterpret_cast<LPVOID>(scratch), 0, MEM_RELEASE);

    if (outcome.resultCode != 0x8000) {
        VirtualFreeEx(process, reinterpret_cast<LPVOID>(base), 0, MEM_RELEASE);
        CloseHandle(process);
        result.error = "remote entry reported failure code " +
                       std::to_string(outcome.resultCode);
        return result;
    }

    CloseHandle(process);
    result.ok = true;
    result.handle.base = base;
    result.handle.entry = entry;
    result.handle.exceptionTable = exceptionTable;
    uint32_t prepareRva = FindExportRva(image, "nexuslab_prepare_unload_v1");
    result.handle.prepare = prepareRva != 0 ? base + prepareRva : 0;
    result.handle.size = image.sizeOfImage;
    return result;
}

UnloadResult Unload(DWORD pid, const Handle& handle) {
    UnloadResult result;
    result.ok = false;
    result.lastError = 0;

    if (pid == 0 || handle.base == 0) {
        result.error = "invalid unload target";
        return result;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                     PROCESS_VM_READ | PROCESS_CREATE_THREAD,
                                 FALSE, pid);
    if (process == nullptr) {
        result.lastError = GetLastError();
        result.error = "OpenProcess failed: " + LastErrorText(result.lastError);
        return result;
    }
    if (handle.prepare != 0) {
        DWORD exitCode = 0;
        std::string threadError;
        if (!RunRemoteCall(process, handle.prepare, 0, 15000, exitCode, threadError)) {
            result.lastError = GetLastError();
            result.error = "prepare call failed: " + threadError;
            CloseHandle(process);
            return result;
        }
        if (exitCode != 0) {
            result.lastError = exitCode;
            result.error = "prepare reported code " + std::to_string(exitCode);
            CloseHandle(process);
            return result;
        }
    }
    if (handle.size != 0) {
        if (!VirtualFreeEx(process, reinterpret_cast<LPVOID>(handle.base), 0, MEM_RELEASE)) {
            result.lastError = GetLastError();
            result.error = "VirtualFreeEx failed: " + LastErrorText(result.lastError);
            CloseHandle(process);
            return result;
        }
    }

    CloseHandle(process);
    result.ok = true;
    return result;
}

}