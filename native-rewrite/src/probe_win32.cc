#include <node_api.h>
#include <windows.h>
#include <tlhelp32.h>
#include <restartmanager.h>
#include <string>
#include <vector>

#include "manual_map.h"

namespace {

const wchar_t* kTargetProcessName = L"QQ.exe";

bool EqualsIgnoreCaseW(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (towlower(a[i]) != towlower(b[i])) {
            return false;
        }
    }
    return true;
}

std::wstring GetProcessImagePath(DWORD pid) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (handle == nullptr) {
        return std::wstring();
    }
    wchar_t buffer[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    std::wstring result;
    if (QueryFullProcessImageNameW(handle, 0, buffer, &size)) {
        result.assign(buffer, size);
    }
    CloseHandle(handle);
    return result;
}

std::wstring BaseNameW(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                     nullptr, 0);
    if (needed <= 0) {
        return std::wstring();
    }
    std::wstring buffer(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        buffer.data(), needed);
    return buffer;
}

std::string WideToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return std::string();
    }
    std::string buffer(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        buffer.data(), needed, nullptr, nullptr);
    return buffer;
}

napi_value MakeInt32(napi_env env, int32_t number) {
    napi_value value;
    napi_create_int32(env, number, &value);
    return value;
}

napi_value MakeUint32(napi_env env, uint32_t number) {
    napi_value value;
    napi_create_uint32(env, number, &value);
    return value;
}

napi_value MakeBool(napi_env env, bool flag) {
    napi_value value;
    napi_get_boolean(env, flag, &value);
    return value;
}

napi_value MakeStringUtf8(napi_env env, const std::string& text) {
    napi_value value;
    napi_create_string_utf8(env, text.c_str(), text.size(), &value);
    return value;
}

napi_value MakeNull(napi_env env) {
    napi_value value;
    napi_get_null(env, &value);
    return value;
}

napi_value MakeError(napi_env env, const std::string& message) {
    napi_value text = MakeStringUtf8(env, message);
    napi_value error;
    napi_create_error(env, nullptr, text, &error);
    return error;
}

struct ProcessEntry {
    DWORD pid;
    std::wstring name;
    std::wstring path;
};

std::vector<ProcessEntry> EnumerateProcesses() {
    std::vector<ProcessEntry> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            ProcessEntry info;
            info.pid = entry.th32ProcessID;
            info.name = entry.szExeFile;
            info.path = GetProcessImagePath(entry.th32ProcessID);
            processes.push_back(info);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return processes;
}

bool IsQqProcess(const ProcessEntry& info) {
    if (!info.path.empty()) {
        return EqualsIgnoreCaseW(BaseNameW(info.path), kTargetProcessName);
    }
    return EqualsIgnoreCaseW(info.name, kTargetProcessName);
}

std::vector<DWORD> CollectQqProcessIds() {
    std::vector<DWORD> pids;
    std::vector<ProcessEntry> processes = EnumerateProcesses();
    for (size_t i = 0; i < processes.size(); ++i) {
        if (IsQqProcess(processes[i])) {
            pids.push_back(processes[i].pid);
        }
    }
    return pids;
}

struct ProcessIdWork {
    napi_async_work work;
    napi_deferred deferred;
    std::vector<DWORD> pids;
    bool ok;
};

void ExecuteProcessIdWork(napi_env env, void* data) {
    (void)env;
    ProcessIdWork* context = static_cast<ProcessIdWork*>(data);
    context->pids = CollectQqProcessIds();
    context->ok = true;
}

void CompleteProcessIdWork(napi_env env, napi_status status, void* data) {
    ProcessIdWork* context = static_cast<ProcessIdWork*>(data);
    if (status != napi_ok || !context->ok) {
        napi_reject_deferred(env, context->deferred,
                             MakeError(env, "process enumeration failed"));
    } else {
        napi_value array;
        napi_create_array_with_length(env, context->pids.size(), &array);
        for (size_t i = 0; i < context->pids.size(); ++i) {
            napi_set_element(env, array, static_cast<uint32_t>(i),
                             MakeUint32(env, context->pids[i]));
        }
        napi_resolve_deferred(env, context->deferred, array);
    }
    napi_delete_async_work(env, context->work);
    delete context;
}

napi_value GetAllMainProcessAsync(napi_env env, napi_callback_info info) {
    size_t argc = 0;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);

    napi_value promise;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);

    ProcessIdWork* context = new ProcessIdWork();
    context->deferred = deferred;
    context->ok = false;

    napi_value resourceName = MakeStringUtf8(env, "GetAllMainProcessAsync");
    napi_create_async_work(env, nullptr, resourceName, ExecuteProcessIdWork,
                           CompleteProcessIdWork, context, &context->work);
    napi_queue_async_work(env, context->work);
    return promise;
}

struct HolderEntry {
    DWORD pid;
    std::wstring name;
};

bool QueryFileHolders(const std::wstring& path, std::vector<HolderEntry>& holders,
                      std::string& error) {
    if (path.empty()) {
        error = "path is empty";
        return false;
    }

    DWORD sessionHandle = 0;
    WCHAR sessionKey[CCH_RM_SESSION_KEY + 1] = {0};
    DWORD result = RmStartSession(&sessionHandle, 0, sessionKey);
    if (result != ERROR_SUCCESS) {
        error = "RmStartSession failed: " + std::to_string(static_cast<int>(result));
        return false;
    }

    const wchar_t* files[1] = {path.c_str()};
    result = RmRegisterResources(sessionHandle, 1, files, 0, nullptr, 0, nullptr);
    if (result != ERROR_SUCCESS) {
        RmEndSession(sessionHandle);
        error = "RmRegisterResources failed: " + std::to_string(static_cast<int>(result));
        return false;
    }

    UINT needed = 0;
    UINT held = 0;
    DWORD reasons = RmRebootReasonNone;
    result = RmGetList(sessionHandle, &needed, &held, nullptr, &reasons);

    if (result == ERROR_SUCCESS && held == 0) {
        RmEndSession(sessionHandle);
        return true;
    }

    if (result != ERROR_MORE_DATA) {
        RmEndSession(sessionHandle);
        error = "RmGetList failed: " + std::to_string(static_cast<int>(result));
        return false;
    }

    std::vector<RM_PROCESS_INFO> buffer;
    for (int round = 0; round < 8; ++round) {
        buffer.resize(needed);
        held = needed;
        result = RmGetList(sessionHandle, &needed, &held, buffer.data(), &reasons);
        if (result == ERROR_SUCCESS) {
            break;
        }
        if (result != ERROR_MORE_DATA) {
            RmEndSession(sessionHandle);
            error = "RmGetList fill failed: " + std::to_string(static_cast<int>(result));
            return false;
        }
    }
    if (result != ERROR_SUCCESS) {
        RmEndSession(sessionHandle);
        error = "RmGetList still unstable after retries: " + std::to_string(static_cast<int>(result));
        return false;
    }

    for (UINT i = 0; i < held; ++i) {
        HolderEntry entry;
        entry.pid = buffer[i].Process.dwProcessId;
        entry.name.assign(buffer[i].strAppName);
        holders.push_back(entry);
    }

    RmEndSession(sessionHandle);
    return true;
}

struct HolderWork {
    napi_async_work work;
    napi_deferred deferred;
    std::wstring path;
    std::vector<HolderEntry> holders;
    std::string error;
    bool ok;
};

void ExecuteHolderWork(napi_env env, void* data) {
    (void)env;
    HolderWork* context = static_cast<HolderWork*>(data);
    std::string error;
    std::vector<HolderEntry> holders;
    if (QueryFileHolders(context->path, holders, error)) {
        context->holders = holders;
        context->ok = true;
    } else {
        context->error = error;
        context->ok = false;
    }
}

void CompleteHolderWork(napi_env env, napi_status status, void* data) {
    HolderWork* context = static_cast<HolderWork*>(data);
    if (status != napi_ok || !context->ok) {
        std::string message = context->error.empty() ? "getFileHolders failed" : context->error;
        napi_reject_deferred(env, context->deferred, MakeError(env, message));
    } else {
        napi_value array;
        napi_create_array_with_length(env, context->holders.size(), &array);
        for (size_t i = 0; i < context->holders.size(); ++i) {
            napi_value object;
            napi_create_object(env, &object);
            napi_set_named_property(env, object, "pid",
                                    MakeUint32(env, context->holders[i].pid));
            napi_set_named_property(env, object, "name",
                                    MakeStringUtf8(env, WideToUtf8(context->holders[i].name)));
            napi_set_element(env, array, static_cast<uint32_t>(i), object);
        }
        napi_resolve_deferred(env, context->deferred, array);
    }
    napi_delete_async_work(env, context->work);
    delete context;
}

bool ReadStringArgument(napi_env env, napi_value value, std::wstring& result) {
    napi_valuetype type;
    if (napi_typeof(env, value, &type) != napi_ok || type != napi_string) {
        return false;
    }
    size_t length = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok) {
        return false;
    }
    std::string utf8(length, '\0');
    if (napi_get_value_string_utf8(env, value, utf8.data(), length + 1, &length) != napi_ok) {
        return false;
    }
    result = Utf8ToWide(utf8);
    return true;
}

napi_value GetFileHoldersAsync(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1) {
        napi_throw(env, MakeError(env, "path is required"));
        return nullptr;
    }

    std::wstring path;
    if (!ReadStringArgument(env, args[0], path)) {
        napi_throw(env, MakeError(env, "path must be a string"));
        return nullptr;
    }

    napi_value promise;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);

    HolderWork* context = new HolderWork();
    context->deferred = deferred;
    context->path = path;
    context->ok = false;

    napi_value resourceName = MakeStringUtf8(env, "GetFileHoldersAsync");
    napi_create_async_work(env, nullptr, resourceName, ExecuteHolderWork,
                           CompleteHolderWork, context, &context->work);
    napi_queue_async_work(env, context->work);
    return promise;
}

struct IntegrityReport {
    DWORD pid;
    bool hasExecutablePath;
    std::string executablePath;
    bool processOk;
    uint32_t processRid;
    std::string processError;
    bool fileOk;
    std::string fileError;
};

std::string DescribeIntegrityLevel(uint32_t rid) {
    if (rid >= 0x4000) {
        return "System";
    }
    if (rid >= 0x3000) {
        return "High";
    }
    if (rid >= 0x2000) {
        return "Medium";
    }
    if (rid >= 0x1000) {
        return "Low";
    }
    return "Untrusted";
}

bool ReadProcessIntegrity(DWORD pid, uint32_t& rid, std::string& error) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) {
        error = "OpenProcess failed: " + std::to_string(static_cast<int>(GetLastError()));
        return false;
    }

    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        error = "OpenProcessToken failed: " + std::to_string(static_cast<int>(GetLastError()));
        CloseHandle(process);
        return false;
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &needed);
    if (needed == 0) {
        error = "GetTokenInformation size failed: " +
                std::to_string(static_cast<int>(GetLastError()));
        CloseHandle(token);
        CloseHandle(process);
        return false;
    }

    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), needed, &needed)) {
        error = "GetTokenInformation failed: " +
                std::to_string(static_cast<int>(GetLastError()));
        CloseHandle(token);
        CloseHandle(process);
        return false;
    }

    TOKEN_MANDATORY_LABEL* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
    if (label->Label.Sid == nullptr) {
        error = "integrity SID missing";
        CloseHandle(token);
        CloseHandle(process);
        return false;
    }

    DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
    if (count == 0) {
        error = "integrity SID has no sub authority";
        CloseHandle(token);
        CloseHandle(process);
        return false;
    }

    rid = static_cast<uint32_t>(*GetSidSubAuthority(label->Label.Sid, count - 1));
    CloseHandle(token);
    CloseHandle(process);
    return true;
}

struct IntegrityWork {
    napi_async_work work;
    napi_deferred deferred;
    IntegrityReport report;
    bool ok;
};

void ExecuteIntegrityWork(napi_env env, void* data) {
    (void)env;
    IntegrityWork* context = static_cast<IntegrityWork*>(data);
    IntegrityReport& report = context->report;
    report.pid = GetCurrentProcessId();
    report.hasExecutablePath = false;
    report.processOk = false;
    report.fileOk = false;

    std::wstring path = GetProcessImagePath(report.pid);
    if (!path.empty()) {
        report.hasExecutablePath = true;
        report.executablePath = WideToUtf8(path);
    }

    uint32_t rid = 0;
    std::string error;
    if (ReadProcessIntegrity(report.pid, rid, error)) {
        report.processOk = true;
        report.processRid = rid;
    } else {
        report.processError = error;
    }

    std::vector<HolderEntry> holders;
    std::string holderError;
    if (!path.empty() && QueryFileHolders(path, holders, holderError)) {
        report.fileOk = true;
    } else {
        report.fileError = holderError.empty() ? "file label unavailable" : holderError;
    }

    context->ok = true;
}

napi_value BuildIntegrityResult(napi_env env, const IntegrityReport& report) {
    napi_value root;
    napi_create_object(env, &root);
    napi_set_named_property(env, root, "pid", MakeUint32(env, report.pid));

    if (report.hasExecutablePath) {
        napi_set_named_property(env, root, "executablePath",
                                MakeStringUtf8(env, report.executablePath));
    } else {
        napi_set_named_property(env, root, "executablePath", MakeNull(env));
    }

    napi_value processObject;
    napi_create_object(env, &processObject);
    if (report.processOk) {
        napi_set_named_property(env, processObject, "status", MakeStringUtf8(env, "ok"));
        napi_set_named_property(env, processObject, "rid", MakeUint32(env, report.processRid));
        napi_set_named_property(env, processObject, "level",
                                MakeStringUtf8(env, DescribeIntegrityLevel(report.processRid)));
    } else {
        napi_set_named_property(env, processObject, "status", MakeStringUtf8(env, "error"));
        napi_set_named_property(env, processObject, "operation",
                                MakeStringUtf8(env, "readProcessIntegrity"));
        napi_set_named_property(env, processObject, "code", MakeInt32(env, 0));
        napi_set_named_property(env, processObject, "message",
                                MakeStringUtf8(env, report.processError));
    }
    napi_set_named_property(env, root, "process", processObject);

    napi_value fileObject;
    napi_create_object(env, &fileObject);
    if (report.fileOk) {
        napi_set_named_property(env, fileObject, "status", MakeStringUtf8(env, "ok"));
        napi_set_named_property(env, fileObject, "label", MakeNull(env));
    } else {
        napi_set_named_property(env, fileObject, "status", MakeStringUtf8(env, "error"));
        napi_set_named_property(env, fileObject, "operation",
                                MakeStringUtf8(env, "readFileLabel"));
        napi_set_named_property(env, fileObject, "code", MakeInt32(env, 0));
        napi_set_named_property(env, fileObject, "message",
                                MakeStringUtf8(env, report.fileError));
    }
    napi_set_named_property(env, root, "file", fileObject);

    return root;
}

void CompleteIntegrityWork(napi_env env, napi_status status, void* data) {
    IntegrityWork* context = static_cast<IntegrityWork*>(data);
    if (status != napi_ok || !context->ok) {
        napi_reject_deferred(env, context->deferred,
                             MakeError(env, "runtime integrity probe failed"));
    } else {
        napi_resolve_deferred(env, context->deferred,
                              BuildIntegrityResult(env, context->report));
    }
    napi_delete_async_work(env, context->work);
    delete context;
}

napi_value GetRuntimeIntegrityAsync(napi_env env, napi_callback_info info) {
    size_t argc = 0;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);

    napi_value promise;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);

    IntegrityWork* context = new IntegrityWork();
    context->deferred = deferred;
    context->ok = false;

    napi_value resourceName = MakeStringUtf8(env, "GetRuntimeIntegrityAsync");
    napi_create_async_work(env, nullptr, resourceName, ExecuteIntegrityWork,
                           CompleteIntegrityWork, context, &context->work);
    napi_queue_async_work(env, context->work);
    return promise;
}

napi_value MakeBigUint64(napi_env env, uint64_t number) {
    napi_value value;
    napi_create_bigint_uint64(env, number, &value);
    return value;
}

struct InjectWork {
    napi_async_work work;
    napi_deferred deferred;
    DWORD pid;
    std::wstring dllPath;
    mmap::Result result;
};

void ExecuteInjectWork(napi_env env, void* data) {
    (void)env;
    InjectWork* context = static_cast<InjectWork*>(data);
    context->result = mmap::Inject(context->pid, context->dllPath);
}

void CompleteInjectWork(napi_env env, napi_status status, void* data) {
    InjectWork* context = static_cast<InjectWork*>(data);
    if (status != napi_ok || !context->result.ok) {
        std::string message = context->result.error.empty() ? "inject failed" : context->result.error;
        napi_reject_deferred(env, context->deferred, MakeError(env, message));
    } else {
        napi_value object;
        napi_create_object(env, &object);
        napi_set_named_property(env, object, "base",
                                MakeBigUint64(env, context->result.handle.base));
        napi_set_named_property(env, object, "entry",
                                MakeBigUint64(env, context->result.handle.entry));
        napi_set_named_property(env, object, "exceptionTable",
                                MakeBigUint64(env, context->result.handle.exceptionTable));
        napi_set_named_property(env, object, "prepare",
                                MakeBigUint64(env, context->result.handle.prepare));
        napi_set_named_property(env, object, "size",
                                MakeUint32(env, static_cast<uint32_t>(context->result.handle.size)));
        napi_resolve_deferred(env, context->deferred, object);
    }
    napi_delete_async_work(env, context->work);
    delete context;
}

napi_value LoadModuleManualAsync(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 2) {
        napi_throw(env, MakeError(env, "pid and dylibPath are required"));
        return nullptr;
    }

    napi_valuetype pidType;
    if (napi_typeof(env, args[0], &pidType) != napi_ok || pidType != napi_number) {
        napi_throw(env, MakeError(env, "pid must be a number"));
        return nullptr;
    }

    uint32_t pid = 0;
    if (napi_get_value_uint32(env, args[0], &pid) != napi_ok || pid == 0) {
        napi_throw(env, MakeError(env, "pid must be a positive integer"));
        return nullptr;
    }

    std::wstring dllPath;
    if (!ReadStringArgument(env, args[1], dllPath) || dllPath.empty()) {
        napi_throw(env, MakeError(env, "dylibPath must be a non-empty string"));
        return nullptr;
    }

    napi_value promise;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);

    InjectWork* context = new InjectWork();
    context->deferred = deferred;
    context->pid = pid;
    context->dllPath = dllPath;

    napi_value resourceName = MakeStringUtf8(env, "LoadModuleManualAsync");
    napi_create_async_work(env, nullptr, resourceName, ExecuteInjectWork,
                           CompleteInjectWork, context, &context->work);
    napi_queue_async_work(env, context->work);
    return promise;
}

struct UnloadWork {
    napi_async_work work;
    napi_deferred deferred;
    DWORD pid;
    mmap::Handle handle;
    mmap::UnloadResult result;
};

void ExecuteUnloadWork(napi_env env, void* data) {
    (void)env;
    UnloadWork* context = static_cast<UnloadWork*>(data);
    context->result = mmap::Unload(context->pid, context->handle);
}

void CompleteUnloadWork(napi_env env, napi_status status, void* data) {
    UnloadWork* context = static_cast<UnloadWork*>(data);
    if (status != napi_ok || !context->result.ok) {
        std::string message = context->result.error.empty() ? "unload failed" : context->result.error;
        napi_reject_deferred(env, context->deferred, MakeError(env, message));
    } else {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        napi_resolve_deferred(env, context->deferred, undefined);
    }
    napi_delete_async_work(env, context->work);
    delete context;
}

bool ReadBigUint64Property(napi_env env, napi_value object, const char* name, uint64_t& out) {
    napi_value property;
    if (napi_get_named_property(env, object, name, &property) != napi_ok) {
        return false;
    }
    napi_valuetype type;
    if (napi_typeof(env, property, &type) != napi_ok) {
        return false;
    }
    if (type == napi_bigint) {
        bool lossless = false;
        return napi_get_value_bigint_uint64(env, property, &out, &lossless) == napi_ok;
    }
    if (type == napi_number) {
        double raw = 0;
        if (napi_get_value_double(env, property, &raw) != napi_ok) {
            return false;
        }
        out = static_cast<uint64_t>(raw);
        return true;
    }
    return false;
}

napi_value UnloadModuleManualAsync(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 2) {
        napi_throw(env, MakeError(env, "pid and handle are required"));
        return nullptr;
    }

    napi_valuetype pidType;
    if (napi_typeof(env, args[0], &pidType) != napi_ok || pidType != napi_number) {
        napi_throw(env, MakeError(env, "pid must be a number"));
        return nullptr;
    }

    uint32_t pid = 0;
    if (napi_get_value_uint32(env, args[0], &pid) != napi_ok || pid == 0) {
        napi_throw(env, MakeError(env, "pid must be a positive integer"));
        return nullptr;
    }

    napi_valuetype handleType;
    if (napi_typeof(env, args[1], &handleType) != napi_ok || handleType != napi_object) {
        napi_throw(env, MakeError(env, "handle must be an object"));
        return nullptr;
    }

    mmap::Handle handle;
    handle.base = 0;
    handle.entry = 0;
    handle.exceptionTable = 0;
    handle.prepare = 0;
    handle.size = 0;

    if (!ReadBigUint64Property(env, args[1], "base", handle.base) || handle.base == 0) {
        napi_throw(env, MakeError(env, "handle.base is required"));
        return nullptr;
    }
    ReadBigUint64Property(env, args[1], "size", handle.size);

    napi_value promise;
    napi_deferred deferred;
    napi_create_promise(env, &deferred, &promise);

    UnloadWork* context = new UnloadWork();
    context->deferred = deferred;
    context->pid = pid;
    context->handle = handle;

    napi_value resourceName = MakeStringUtf8(env, "UnloadModuleManualAsync");
    napi_create_async_work(env, nullptr, resourceName, ExecuteUnloadWork,
                           CompleteUnloadWork, context, &context->work);
    napi_queue_async_work(env, context->work);
    return promise;
}

napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor properties[] = {
        {"getAllMainProcessAsync", nullptr, GetAllMainProcessAsync, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"getFileHoldersAsync", nullptr, GetFileHoldersAsync, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"getRuntimeIntegrityAsync", nullptr, GetRuntimeIntegrityAsync, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"loadModuleManualAsync", nullptr, LoadModuleManualAsync, nullptr, nullptr, nullptr,
         napi_default, nullptr},
        {"unloadModuleManualAsync", nullptr, UnloadModuleManualAsync, nullptr, nullptr, nullptr,
         napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
    return exports;
}

}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)