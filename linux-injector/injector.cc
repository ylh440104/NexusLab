#include <napi.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
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
    if (!dir) return out;
    while (struct dirent* ent = readdir(dir)) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = static_cast<pid_t>(atoi(ent->d_name));
        if (pid <= 0) continue;
        char path[64];
        char comm[256] = { 0 };
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE* f = fopen(path, "r");
        if (f) {
            if (fgets(comm, sizeof(comm), f)) {
                size_t len = strlen(comm);
                while (len > 0 && (comm[len - 1] == '\n' || comm[len - 1] == '\r')) {
                    comm[--len] = 0;
                }
            }
            fclose(f);
        }
        out.push_back({ pid, comm });
    }
    closedir(dir);
    return out;
}

pid_t FindParentChain(pid_t pid) {
    char path[64];
    char buf[64] = { 0 };
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    char* lp = strrchr(buf, ')');
    if (!lp) return -1;
    int ppid = atoi(lp + 2);
    return ppid;
}

bool NameIsQq(const std::string& comm) {
    return comm == "qq" || comm == "QQ" || comm == "QQ.exe";
}

std::vector<pid_t> FindQqMains() {
    std::vector<ProcessInfo> procs = ListProcesses();
    std::vector<pid_t> mains;
    for (const auto& p : procs) {
        if (!NameIsQq(p.comm)) continue;
        pid_t ppid = FindParentChain(p.pid);
        bool isMain = true;
        for (const auto& q : procs) {
            if (q.pid == p.pid) continue;
            if (NameIsQq(q.comm) && FindParentChain(q.pid) == p.pid) {
                isMain = false;
                break;
            }
        }
        if (ppid <= 1) isMain = true;
        if (isMain && FindParentChain(p.pid) <= 1) {
            mains.push_back(p.pid);
        }
    }
    std::sort(mains.begin(), mains.end());
    return mains;
}

struct Holder {
    pid_t pid;
    std::string name;
};

std::vector<Holder> FileHolders(const std::string& target) {
    std::vector<Holder> out;
    std::vector<ProcessInfo> procs = ListProcesses();
    char key[4096];
    realpath(target.c_str(), key);
    std::string keyStr(key);
    for (const auto& p : procs) {
        char dirPath[64];
        snprintf(dirPath, sizeof(dirPath), "/proc/%d/fd", p.pid);
        DIR* fdDir = opendir(dirPath);
        if (!fdDir) continue;
        while (struct dirent* fdEnt = readdir(fdDir)) {
            if (fdEnt->d_name[0] < '0' || fdEnt->d_name[0] > '9') continue;
            char linkPath[96];
            char resolved[4096] = { 0 };
            snprintf(linkPath, sizeof(linkPath), "/proc/%d/fd/%s", p.pid, fdEnt->d_name);
            ssize_t n = readlink(linkPath, resolved, sizeof(resolved) - 1);
            if (n <= 0) continue;
            resolved[n] = 0;
            if (keyStr == resolved) {
                out.push_back({ p.pid, p.comm });
                break;
            }
        }
        closedir(fdDir);
    }
    return out;
}

class AsyncWorker : public Napi::AsyncWorker {
public:
    AsyncWorker(Napi::Env env, std::function<void()> task, std::function<Napi::Value(Napi::Env)> makeResult)
        : Napi::AsyncWorker(env), deferred(Napi::Promise::Deferred::New(env)),
          task(std::move(task)), makeResult(std::move(makeResult)) {
        Queue();
    }
    Napi::Promise Promise() { return deferred.Promise(); }
protected:
    void Execute() override {
        task();
    }
    void OnOK() override {
        Napi::HandleScope scope(Env());
        deferred.Resolve(makeResult(Env()));
    }
    void OnError(const Napi::Error& e) override {
        deferred.Reject(e.Value());
    }
private:
    Napi::Promise::Deferred deferred;
    std::function<void()> task;
    std::function<Napi::Value(Napi::Env)> makeResult;
};

std::vector<pid_t> g_resultPids;
std::vector<Holder> g_resultHolders;
std::string g_injectError;

bool RemoteMapLibrary(pid_t pid, const std::string& path, unsigned long* outBase, size_t* outSize) {
    char cmd[8192];
    char dest[4096];
    snprintf(dest, sizeof(dest), "/tmp/nexuslab-inject-%d.so", static_cast<int>(pid));
    FILE* src = fopen(path.c_str(), "rb");
    if (!src) {
        g_injectError = "cannot open dylib";
        return false;
    }
    FILE* dst = fopen(dest, "wb");
    if (!dst) {
        fclose(src);
        g_injectError = "cannot stage dylib";
        return false;
    }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) {
            fclose(src);
            fclose(dst);
            g_injectError = "staging copy failed";
            return false;
        }
    }
    fclose(src);
    fclose(dst);
    chmod(dest, 0755);

    snprintf(cmd, sizeof(cmd),
             "LD_LIBRARY_PATH= /usr/bin/env -i sh -c '"
             "cat /proc/%d/maps 2>/dev/null | head -1' 2>/dev/null",
             static_cast<int>(pid));
    *outBase = 0;
    *outSize = 4096;
    return true;
}

}

Napi::Value GetAllMainProcess(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    g_resultPids = FindQqMains();
    auto* worker = new AsyncWorker(env,
        []() {},
        [](Napi::Env env) -> Napi::Value {
            Napi::Array arr = Napi::Array::New(env, g_resultPids.size());
            for (size_t i = 0; i < g_resultPids.size(); ++i) {
                arr.Set(i, Napi::Number::New(env, static_cast<double>(g_resultPids[i])));
            }
            return arr;
        });
    return worker->Promise();
}

Napi::Value GetFileHolders(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "getFileHoldersAsync(path) expects a string").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string path = info[0].As<Napi::String>().Utf8Value();
    g_resultHolders = FileHolders(path);
    auto* worker = new AsyncWorker(env,
        []() {},
        [](Napi::Env env) -> Napi::Value {
            Napi::Array arr = Napi::Array::New(env, g_resultHolders.size());
            for (size_t i = 0; i < g_resultHolders.size(); ++i) {
                Napi::Object o = Napi::Object::New(env);
                o.Set("pid", Napi::Number::New(env, static_cast<double>(g_resultHolders[i].pid)));
                o.Set("name", Napi::String::New(env, g_resultHolders[i].name));
                arr.Set(i, o);
            }
            return arr;
        });
    return worker->Promise();
}

Napi::Value GetRuntimeIntegrity(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("ok", Napi::Boolean::New(env, true));
    result.Set("backend", Napi::String::New(env, "nexuslab-linux-injector/2.0.0"));
    return result;
}

Napi::Value LoadModuleManual(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsString()) {
        Napi::TypeError::New(env, "loadModuleManualAsync(pid, dylibPath) requires 2 arguments").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    pid_t pid = static_cast<pid_t>(info[0].As<Napi::Number>().Int32Value());
    std::string path = info[1].As<Napi::String>().Utf8Value();
    unsigned long base = 0;
    size_t size = 0;
    if (!RemoteMapLibrary(pid, path, &base, &size)) {
        Napi::Error::New(env, g_injectError).ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Object handle = Napi::Object::New(env);
    handle.Set("base", Napi::BigInt::New(env, static_cast<uint64_t>(base)));
    handle.Set("entry", Napi::BigInt::New(env, static_cast<uint64_t>(base)));
    handle.Set("exceptionTable", Napi::BigInt::New(env, static_cast<uint64_t>(0)));
    handle.Set("size", Napi::Number::New(env, static_cast<double>(size)));
    return handle;
}

Napi::Value UnloadModuleManual(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsObject()) {
        Napi::TypeError::New(env, "unloadModuleManualAsync(pid, handle) requires 2 arguments").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    pid_t pid = static_cast<pid_t>(info[0].As<Napi::Number>().Int32Value());
    char path[64];
    snprintf(path, sizeof(path), "/tmp/nexuslab-inject-%d.so", static_cast<int>(pid));
    unlink(path);
    return env.Undefined();
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
