#include <napi.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "core.h"
namespace {

using namespace nexuslab_linux;

class PromiseTask : public Napi::AsyncWorker {
public:
    PromiseTask(Napi::Env env, std::function<void()> body,
                std::function<Napi::Value(Napi::Env)> produce)
        : Napi::AsyncWorker(env),
          deferred_(Napi::Promise::Deferred::New(env)),
          body_(std::move(body)),
          produce_(std::move(produce)) {}

    Napi::Promise Deferred() const { return deferred_.Promise(); }

protected:
    void Execute() override {
        failure_.clear();
        try {
            body_();
        } catch (const std::exception& error) {
            failure_ = error.what();
        } catch (...) {
            failure_ = "unexpected native failure";
        }
    }

    void OnOK() override {
        Napi::HandleScope scope(Env());
        if (!failure_.empty()) {
            deferred_.Reject(Napi::String::New(Env(), failure_));
            return;
        }
        Napi::Value value = Env().Undefined();
        try {
            value = produce_(Env());
        } catch (const std::exception& error) {
            deferred_.Reject(Napi::String::New(Env(), error.what()));
            return;
        } catch (...) {
            deferred_.Reject(Napi::String::New(Env(), "failed to build result"));
            return;
        }
        deferred_.Resolve(value);
    }

    void OnError(const Napi::Error& error) override {
        deferred_.Reject(error.Value());
    }

private:
    Napi::Promise::Deferred deferred_;
    std::function<void()> body_;
    std::function<Napi::Value(Napi::Env)> produce_;
    std::string failure_;
};

Napi::Object BuildHolderObject(Napi::Env env, const FileHolder& holder) {
    Napi::Object object = Napi::Object::New(env);
    object.Set("pid", Napi::Number::New(env, static_cast<double>(holder.pid)));
    object.Set("name", Napi::String::New(env, holder.name));
    return object;
}

std::string ReadStringArgument(const Napi::CallbackInfo& info, size_t index) {
    if (info.Length() <= index || !info[index].IsString()) {
        return std::string();
    }
    return info[index].As<Napi::String>().Utf8Value();
}

pid_t ReadPidArgument(const Napi::CallbackInfo& info, size_t index) {
    if (info.Length() <= index || !info[index].IsNumber()) {
        return 0;
    }
    const double raw = info[index].As<Napi::Number>().DoubleValue();
    if (raw <= 0) {
        return 0;
    }
    return static_cast<pid_t>(raw);
}

Napi::Promise RejectedPromise(Napi::Env env, const std::string& reason) {
    Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);
    deferred.Reject(Napi::String::New(env, reason));
    return deferred.Promise();
}

Napi::Value StartTask(Napi::Env env, PromiseTask* task) {
    Napi::Promise promise = task->Deferred();
    task->Queue();
    return promise;
}

}

namespace {

Napi::Value ListMainProcesses(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto shared = std::make_shared<std::vector<pid_t>>();

    auto* task = new PromiseTask(
        env, [shared]() { *shared = FindMainProcesses(); },
        [shared](Napi::Env scope) -> Napi::Value {
            Napi::Array array = Napi::Array::New(scope, shared->size());
            uint32_t cursor = 0;
            for (pid_t pid : *shared) {
                Napi::Object entry = Napi::Object::New(scope);
                entry.Set("pid", Napi::Number::New(scope, static_cast<double>(pid)));
                entry.Set("name", Napi::String::New(scope, "qq"));
                array.Set(cursor++, entry);
            }
            return array;
        });

    return StartTask(env, task);
}

Napi::Value ListFileHolders(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const std::string target = ReadStringArgument(info, 0);
    if (target.empty()) {
        return RejectedPromise(env, "target path is required");
    }

    auto shared = std::make_shared<std::vector<FileHolder>>();

    auto* task = new PromiseTask(
        env, [shared, target]() { *shared = QueryFileHolders(target); },
        [shared](Napi::Env scope) -> Napi::Value {
            Napi::Array array = Napi::Array::New(scope, shared->size());
            uint32_t cursor = 0;
            for (const FileHolder& holder : *shared) {
                array.Set(cursor++, BuildHolderObject(scope, holder));
            }
            return array;
        });

    return StartTask(env, task);
}

Napi::Value LoadModule(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const pid_t pid = ReadPidArgument(info, 0);
    const std::string libraryPath = ReadStringArgument(info, 1);

    if (pid == 0) {
        return RejectedPromise(env, "a valid target pid is required");
    }
    if (libraryPath.empty()) {
        return RejectedPromise(env, "a library path is required");
    }

    auto handle = std::make_shared<unsigned long>(0);
    auto base = std::make_shared<unsigned long>(0);
    auto injected = std::make_shared<bool>(false);

    auto* task = new PromiseTask(
        env,
        [handle, base, injected, pid, libraryPath]() {
            *injected = InjectLibrary(pid, libraryPath, handle.get(), base.get());
        },
        [handle, base, injected](Napi::Env scope) -> Napi::Value {
            Napi::Object result = Napi::Object::New(scope);
            result.Set("success", Napi::Boolean::New(scope, *injected));
            result.Set("injected", Napi::Boolean::New(scope, *injected));
            result.Set("handle", Napi::Number::New(scope, static_cast<double>(*handle)));
            result.Set("base", Napi::Number::New(scope, static_cast<double>(*base)));
            result.Set("error", Napi::String::New(scope, g_lastError));
            return result;
        });

    return StartTask(env, task);
}

Napi::Value UnloadModule(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const pid_t pid = ReadPidArgument(info, 0);
    const std::string libraryPath = ReadStringArgument(info, 1);

    if (pid == 0 || libraryPath.empty()) {
        return RejectedPromise(env, "pid and library path are required");
    }

    auto handle = std::make_shared<unsigned long>(0);
    auto base = std::make_shared<unsigned long>(0);
    auto injected = std::make_shared<bool>(false);

    auto* task = new PromiseTask(
        env,
        [handle, base, injected, pid, libraryPath]() {
            *injected = InjectLibrary(pid, libraryPath, handle.get(), base.get());
        },
        [handle, base, injected](Napi::Env scope) -> Napi::Value {
            Napi::Object result = Napi::Object::New(scope);
            result.Set("success", Napi::Boolean::New(scope, *injected));
            result.Set("handle", Napi::Number::New(scope, static_cast<double>(*handle)));
            result.Set("base", Napi::Number::New(scope, static_cast<double>(*base)));
            result.Set("error", Napi::String::New(scope, g_lastError));
            return result;
        });

    return StartTask(env, task);
}

Napi::Value CallSymbol(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const pid_t pid = ReadPidArgument(info, 0);
    const std::string symbol = ReadStringArgument(info, 1);

    if (pid == 0) {
        return RejectedPromise(env, "a valid target pid is required");
    }
    if (symbol.empty()) {
        return RejectedPromise(env, "a symbol name is required");
    }

    auto value = std::make_shared<unsigned long>(0);
    auto called = std::make_shared<bool>(false);

    auto* task = new PromiseTask(
        env,
        [value, called, pid, symbol]() {
            const unsigned long address = ResolveRemoteSymbol(pid, symbol.c_str());
            if (address == 0) {
                g_lastError = "cannot resolve symbol inside target";
                return;
            }
            if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
                g_lastError = "ptrace attach rejected";
                return;
            }
            int status = 0;
            if (waitpid(pid, &status, __WALL) < 0) {
                ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                g_lastError = "target did not stop";
                return;
            }
            *called = CallRemoteFunction(pid, address, std::vector<unsigned long>(), value.get());
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        },
        [value, called](Napi::Env scope) -> Napi::Value {
            Napi::Object result = Napi::Object::New(scope);
            result.Set("success", Napi::Boolean::New(scope, *called));
            result.Set("value", Napi::Number::New(scope, static_cast<double>(*value)));
            result.Set("error", Napi::String::New(scope, g_lastError));
            return result;
        });

    return StartTask(env, task);
}

Napi::Value DescribeBackend(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("backend", Napi::String::New(env, "nexuslab-linux-injector/3.0.0"));
#if defined(__aarch64__)
    result.Set("arch", Napi::String::New(env, "arm64"));
#else
    result.Set("arch", Napi::String::New(env, "x64"));
#endif
    return result;
}

}

static Napi::Object InitializeModule(Napi::Env env, Napi::Object exports) {
    exports.Set("getAllMainProcessAsync", Napi::Function::New(env, ListMainProcesses));
    exports.Set("getFileHoldersAsync", Napi::Function::New(env, ListFileHolders));
    exports.Set("loadModuleManualAsync", Napi::Function::New(env, LoadModule));
    exports.Set("unloadModuleManualAsync", Napi::Function::New(env, UnloadModule));
    exports.Set("callRemoteSymbolAsync", Napi::Function::New(env, CallSymbol));
    exports.Set("describeBackend", Napi::Function::New(env, DescribeBackend));
    return exports;
}

NODE_API_MODULE(nexuslab_linux_injector, InitializeModule)
