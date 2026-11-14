#include <napi.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace {

struct ProcessInfo {
    pid_t pid;
    std::string comm;
};

std::vector<ProcessInfo> ListProcesses() {
    std::vector<ProcessInfo> out;
    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        return out;
    }
    while (struct dirent* ent = readdir(dir)) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') {
            continue;
        }
        pid_t pid = static_cast<pid_t>(atoi(ent->d_name));
        if (pid <= 0) {
            continue;
        }
        char path[64];
        char comm[256] = { 0 };
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE* fp = fopen(path, "r");
        if (fp != nullptr) {
            if (fgets(comm, sizeof(comm), fp) != nullptr) {
                size_t len = strlen(comm);
                while (len > 0 && (comm[len - 1] == '\n' || comm[len - 1] == '\r')) {
                    comm[--len] = 0;
                }
            }
            fclose(fp);
        }
        out.push_back({ pid, comm });
    }
    closedir(dir);
    return out;
}

pid_t ReadParentPid(pid_t pid) {
    char path[64];
    char buf[512] = { 0 };
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE* fp = fopen(path, "r");
    if (fp == nullptr) {
        return -1;
    }
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = 0;
    char* rparen = strrchr(buf, ')');
    if (rparen == nullptr) {
        return -1;
    }
    return static_cast<pid_t>(atoi(rparen + 2));
}

bool IsQqName(const std::string& comm) {
    return comm == "qq" || comm == "QQ";
}

std::vector<pid_t> FindQqMains() {
    std::vector<ProcessInfo> procs = ListProcesses();
    std::vector<pid_t> mains;
    for (const auto& p : procs) {
        if (!IsQqName(p.comm)) {
            continue;
        }
        bool hasQqChild = false;
        for (const auto& q : procs) {
            if (q.pid == p.pid || !IsQqName(q.comm)) {
                continue;
            }
            if (ReadParentPid(q.pid) == p.pid) {
                hasQqChild = true;
                break;
            }
        }
        pid_t ppid = ReadParentPid(p.pid);
        if (!hasQqChild && ppid > 0) {
            mains.push_back(p.pid);
        }
    }
    if (mains.empty()) {
        for (const auto& p : procs) {
            if (IsQqName(p.comm) && ReadParentPid(p.pid) <= 1) {
                mains.push_back(p.pid);
            }
        }
    }
    return mains;
}

struct Holder {
    pid_t pid;
    std::string name;
};

std::vector<Holder> FileHolders(const std::string& target) {
    std::vector<Holder> out;
    char resolved[PATH_MAX] = { 0 };
    if (realpath(target.c_str(), resolved) == nullptr) {
        snprintf(resolved, sizeof(resolved), "%s", target.c_str());
    }
    std::vector<ProcessInfo> procs = ListProcesses();
    for (const auto& p : procs) {
        char fdDir[64];
        snprintf(fdDir, sizeof(fdDir), "/proc/%d/fd", p.pid);
        DIR* dir = opendir(fdDir);
        if (dir == nullptr) {
            continue;
        }
        bool matched = false;
        while (struct dirent* ent = readdir(dir)) {
            if (matched || ent->d_name[0] < '0' || ent->d_name[0] > '9') {
                continue;
            }
            char linkPath[128];
            char link[PATH_MAX] = { 0 };
            snprintf(linkPath, sizeof(linkPath), "/proc/%d/fd/%s", p.pid, ent->d_name);
            ssize_t len = readlink(linkPath, link, sizeof(link) - 1);
            if (len <= 0) {
                continue;
            }
            link[len] = 0;
            if (strcmp(link, resolved) == 0) {
                out.push_back({ p.pid, p.comm });
                matched = true;
            }
        }
        closedir(dir);
    }
    return out;
}

bool ReadMemory(pid_t pid, unsigned long address, void* buffer, size_t length) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    ssize_t n = pread(fd, buffer, length, static_cast<off_t>(address));
    close(fd);
    return n == static_cast<ssize_t>(length);
}

bool WriteMemory(pid_t pid, unsigned long address, const void* buffer, size_t length) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return false;
    }
    ssize_t n = pwrite(fd, buffer, length, static_cast<off_t>(address));
    close(fd);
    return n == static_cast<ssize_t>(length);
}

unsigned long FindModuleBase(pid_t pid, const char* soname) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* fp = fopen(path, "r");
    if (fp == nullptr) {
        return 0;
    }
    char line[1024];
    unsigned long best = 0;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, soname) == nullptr) {
            continue;
        }
        if (strstr(line, " r-xp ") == nullptr && strstr(line, " r--p ") == nullptr) {
            continue;
        }
        unsigned long start = strtoul(line, nullptr, 16);
        if (start != 0 && (best == 0 || start < best)) {
            best = start;
        }
    }
    fclose(fp);
    return best;
}

unsigned long ResolveRemoteSymbol(pid_t pid, const char* symbol) {
    unsigned long local = reinterpret_cast<unsigned long>(dlsym(RTLD_DEFAULT, symbol));
    if (local == 0) {
        return 0;
    }
    Dl_info info;
    if (dladdr(reinterpret_cast<void*>(local), &info) == 0 || info.dli_fbase == nullptr) {
        return 0;
    }
    unsigned long localBase = reinterpret_cast<unsigned long>(info.dli_fbase);
    unsigned long offset = local - localBase;
    unsigned long remoteBase = FindModuleBase(pid, info.dli_fname);
    if (remoteBase == 0) {
        const char* slash = strrchr(info.dli_fname, '/');
        if (slash != nullptr) {
            remoteBase = FindModuleBase(pid, slash + 1);
        }
    }
    if (remoteBase == 0) {
        return 0;
    }
    return remoteBase + offset;
}

bool WaitForStop(pid_t pid, int* outStatus) {
    for (;;) {
        int status = 0;
        pid_t waited = waitpid(pid, &status, __WALL);
        if (waited < 0) {
            return false;
        }
        if (WIFSTOPPED(status)) {
            if (outStatus != nullptr) {
                *outStatus = status;
            }
            return true;
        }
        if (WIFEXITED(status)) {
            return false;
        }
    }
}

#if defined(__aarch64__)
struct RemoteRegs {
    unsigned long regs[34];
};
#define REMOTE_PC(rs) ((rs).regs[32])
#define REMOTE_SP(rs) ((rs).regs[31])
#define REMOTE_SYSNR(rs) ((rs).regs[8])
#define REMOTE_ARG(rs, i) ((rs).regs[i])
#define REMOTE_RET(rs) ((rs).regs[0])
#else
struct RemoteRegs {
    struct user_regs_struct u;
};
#define REMOTE_PC(rs) ((rs).u.rip)
#define REMOTE_SP(rs) ((rs).u.rsp)
#define REMOTE_SYSNR(rs) ((rs).u.orig_rax)
#define REMOTE_ARG(rs, i) ((i) == 0 ? (rs).u.rdi : (i) == 1 ? (rs).u.rsi : (i) == 2 ? (rs).u.rdx : (i) == 3 ? (rs).u.r10 : (i) == 4 ? (rs).u.r8 : (rs).u.r9)
#define REMOTE_RET(rs) ((rs).u.rax)
#endif

bool GetRegs(pid_t pid, RemoteRegs* out) {
#if defined(__aarch64__)
    struct iovec io;
    io.iov_base = out->regs;
    io.iov_len = sizeof(out->regs);
    return ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
#else
    return ptrace(PTRACE_GETREGS, pid, nullptr, &out->u) == 0;
#endif
}

bool SetRegs(pid_t pid, const RemoteRegs* in) {
#if defined(__aarch64__)
    struct iovec io;
    io.iov_base = const_cast<unsigned long*>(in->regs);
    io.iov_len = sizeof(in->regs);
    return ptrace(PTRACE_SETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
#else
    return ptrace(PTRACE_SETREGS, pid, nullptr, const_cast<struct user_regs_struct*>(&in->u)) == 0;
#endif
}

struct RegsBackup {
    RemoteRegs regs;
    bool valid = false;
};

std::string g_error;

bool RemoteCall(pid_t pid, unsigned long fnAddress, const std::vector<unsigned long>& args,
                RegsBackup* backup, unsigned long* outRet) {
    RemoteRegs regs;
    if (!GetRegs(pid, &regs)) {
        g_error = "cannot read target registers";
        return false;
    }
    if (backup != nullptr) {
        backup->regs = regs;
        backup->valid = true;
    }

    unsigned long retAddr = REMOTE_PC(regs);
    unsigned long sp = REMOTE_SP(regs) - 16;
    sp &= ~0xFUL;
    if (!WriteMemory(pid, sp, &retAddr, sizeof(retAddr))) {
        g_error = "cannot write return address to target stack";
        return false;
    }

    for (size_t i = 0; i < args.size() && i < 6; ++i) {
        REMOTE_ARG(regs, i) = args[i];
    }
    REMOTE_PC(regs) = fnAddress;
    REMOTE_SP(regs) = sp;

    if (!SetRegs(pid, &regs)) {
        g_error = "cannot set target registers";
        return false;
    }

    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0) {
        g_error = "cannot resume target";
        return false;
    }

    int status = 0;
    if (!WaitForStop(pid, &status)) {
        g_error = "target died during remote call";
        return false;
    }

    RemoteRegs after;
    if (GetRegs(pid, &after)) {
        if (outRet != nullptr) {
            *outRet = REMOTE_RET(after);
        }
    }
    return true;
}

bool InjectLibrary(pid_t pid, const std::string& path, unsigned long* outHandle,
                   unsigned long* outBase) {
    unsigned long dlopenAddr = ResolveRemoteSymbol(pid, "dlopen");
    if (dlopenAddr == 0) {
        g_error = "cannot resolve dlopen in target";
        return false;
    }
    unsigned long dlerrorAddr = ResolveRemoteSymbol(pid, "dlerror");

    const size_t pathLen = path.size() + 1;
    unsigned long remotePath = 0;

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        g_error = "ptrace attach failed (need same uid or CAP_SYS_PTRACE)";
        return false;
    }
    int status = 0;
    if (!WaitForStop(pid, &status)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_error = "target did not stop for ptrace";
        return false;
    }

    RemoteRegs initial;
    if (!GetRegs(pid, &initial)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_error = "cannot read target registers after attach";
        return false;
    }

    unsigned long scratch = (REMOTE_SP(initial) - 8192) & ~0xFUL;
    remotePath = scratch;
    if (!WriteMemory(pid, remotePath, path.c_str(), pathLen)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        g_error = "cannot write library path into target stack";
        return false;
    }

    RegsBackup backup;
    unsigned long handle = 0;
    bool ok = RemoteCall(pid, dlopenAddr, { remotePath, 2 /* RTLD_NOW */ }, &backup, &handle);
    bool restored = false;
    if (backup.valid) {
        restored = SetRegs(pid, &backup.regs);
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    if (!ok) {
        return false;
    }
    if (!restored) {
        g_error = "remote call finished but registers could not be restored";
        return false;
    }
    if (handle == 0) {
        if (dlerrorAddr != 0) {
            RegsBackup errBackup;
            unsigned long errPtr = 0;
            if (RemoteCall(pid, dlerrorAddr, {}, &errBackup, &errPtr) && errPtr != 0) {
                char msg[512] = { 0 };
                if (ReadMemory(pid, errPtr, msg, sizeof(msg) - 1)) {
                    g_error = std::string("dlopen failed in target: ") + msg;
                } else {
                    g_error = "dlopen returned null in target";
                }
            } else {
                g_error = "dlopen returned null in target";
            }
        } else {
            g_error = "dlopen returned null in target";
        }
        return false;
    }
    if (outHandle != nullptr) {
        *outHandle = handle;
    }
    if (outBase != nullptr) {
        *outBase = FindModuleBase(pid, path.c_str());
    }
    return true;
}

}

typedef Napi::Value (*ResultFactory)(Napi::Env);

class TaskWorker : public Napi::AsyncWorker {
public:
    TaskWorker(Napi::Env env, std::function<bool()> task, std::function<Napi::Value(Napi::Env)> factory)
        : Napi::AsyncWorker(env), deferred_(Napi::Promise::Deferred::New(env)),
          task_(std::move(task)), factory_(std::move(factory)) {}
    Napi::Promise Promise() { return deferred_.Promise(); }
    void QueueWork() { Queue(); }

protected:
    void Execute() override {
        if (!task_()) {
            SetError(g_error.empty() ? std::string("operation failed") : g_error);
        }
    }
    void OnOK() override {
        Napi::HandleScope scope(Env());
        deferred_.Resolve(factory_(Env()));
    }
    void OnError(const Napi::Error& err) override {
        deferred_.Reject(err.Value());
    }

private:
    Napi::Promise::Deferred deferred_;
    std::function<bool()> task_;
    std::function<Napi::Value(Napi::Env)> factory_;
};

namespace {
std::vector<pid_t> g_pids;
std::vector<Holder> g_holders;
unsigned long g_handle = 0;
unsigned long g_base = 0;
}

Napi::Value GetAllMainProcess(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto* worker = new TaskWorker(env,
        []() {
            g_error.clear();
            g_pids = FindQqMains();
            return true;
        },
        [](Napi::Env e) {
            Napi::Array arr = Napi::Array::New(e, g_pids.size());
            for (size_t i = 0; i < g_pids.size(); ++i) {
                arr.Set(i, Napi::Number::New(e, static_cast<double>(g_pids[i])));
            }
            return arr;
        });
    auto promise = worker->Promise();
    worker->QueueWork();
    return promise;
}

Napi::Value GetFileHolders(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "getFileHoldersAsync(path): expected string")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string path = info[0].As<Napi::String>().Utf8Value();
    auto* worker = new TaskWorker(env,
        [path]() {
            g_error.clear();
            g_holders = FileHolders(path);
            return true;
        },
        [](Napi::Env e) {
            Napi::Array arr = Napi::Array::New(e, g_holders.size());
            for (size_t i = 0; i < g_holders.size(); ++i) {
                Napi::Object item = Napi::Object::New(e);
                item.Set("pid", Napi::Number::New(e, static_cast<double>(g_holders[i].pid)));
                item.Set("name", Napi::String::New(e, g_holders[i].name));
                arr.Set(i, item);
            }
            return arr;
        });
    auto promise = worker->Promise();
    worker->QueueWork();
    return promise;
}

Napi::Value GetRuntimeIntegrity(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, true));
    result.Set("backend", Napi::String::New(env, "nexuslab-linux-injector/2.1.0"));
    return result;
}

Napi::Value LoadModuleManual(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsString()) {
        Napi::TypeError::New(env, "loadModuleManualAsync(pid, dylibPath) requires 2 arguments")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    pid_t pid = static_cast<pid_t>(info[0].As<Napi::Number>().Int32Value());
    std::string path = info[1].As<Napi::String>().Utf8Value();
    auto* worker = new TaskWorker(env,
        [pid, path]() {
            g_error.clear();
            char resolved[PATH_MAX] = { 0 };
            std::string real = path;
            if (realpath(path.c_str(), resolved) != nullptr) {
                real = resolved;
            }
            return InjectLibrary(pid, real, &g_handle, &g_base);
        },
        [](Napi::Env e) {
            Napi::Object handle = Napi::Object::New(e);
            handle.Set("base", Napi::BigInt::New(e, static_cast<uint64_t>(g_base)));
            handle.Set("entry", Napi::BigInt::New(e, static_cast<uint64_t>(g_handle)));
            handle.Set("exceptionTable", Napi::BigInt::New(e, static_cast<uint64_t>(0)));
            handle.Set("size", Napi::Number::New(e, 0));
            return handle;
        });
    auto promise = worker->Promise();
    worker->QueueWork();
    return promise;
}

Napi::Value UnloadModuleManual(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsObject()) {
        Napi::TypeError::New(env, "unloadModuleManualAsync(pid, handle) requires 2 arguments")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    pid_t pid = static_cast<pid_t>(info[0].As<Napi::Number>().Int32Value());
    auto* worker = new TaskWorker(env,
        [pid]() {
            g_error.clear();
            unsigned long stopAddr = ResolveRemoteSymbol(pid, "nexuslab_linux_hook_stop_dynamic");
            if (stopAddr == 0) {
                return true;
            }
            if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
                g_error = "ptrace attach failed during unload";
                return false;
            }
            int status = 0;
            if (!WaitForStop(pid, &status)) {
                ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                return true;
            }
            RegsBackup backup;
            unsigned long ignored = 0;
            bool ok = RemoteCall(pid, stopAddr, {}, &backup, &ignored);
            if (backup.valid) {
                SetRegs(pid, &backup.regs);
            }
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return ok;
        },
        [](Napi::Env e) {
            return e.Undefined();
        });
    auto promise = worker->Promise();
    worker->QueueWork();
    return promise;
}

Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
    exports.Set("getAllMainProcessAsync", Napi::Function::New(env, GetAllMainProcess));
    exports.Set("getFileHoldersAsync", Napi::Function::New(env, GetFileHolders));
    exports.Set("getRuntimeIntegrityAsync", Napi::Function::New(env, GetRuntimeIntegrity));
    exports.Set("loadModuleManualAsync", Napi::Function::New(env, LoadModuleManual));
    exports.Set("unloadModuleManualAsync", Napi::Function::New(env, UnloadModuleManual));
    return exports;
}

NODE_API_MODULE(nexuslab_linux_injector, InitModule)
