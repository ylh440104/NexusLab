#include "napi_hook.h"
#include "inline_hook.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <cstdarg>
#include <fcntl.h>

namespace nexuslab_napi {
namespace {

typedef struct napi_env__* napi_env;
typedef struct napi_value__* napi_value;
typedef struct napi_callback_info__* napi_callback_info;
typedef struct napi_ref__* napi_ref;
typedef struct napi_deferred__* napi_deferred;
typedef struct napi_handle_scope__* napi_handle_scope;
typedef napi_value (*napi_callback)(napi_env, napi_callback_info);

typedef napi_value (*CreateFunctionFn)(napi_env, const char*, size_t, napi_callback, void*, napi_value*);
typedef int (*GetCbInfoFn)(napi_env, napi_callback_info, size_t*, napi_value*, napi_value*, void**);
typedef int (*GetValueStringUtf8Fn)(napi_env, napi_value, char*, size_t, size_t*);
typedef int (*TypeofFn)(napi_env, napi_value, int*);
typedef int (*GetValueExternalFn)(napi_env, napi_value, void**);
typedef int (*CreateExternalFn)(napi_env, void*, napi_value*);
typedef int (*CreateArrayFn)(napi_env, uint32_t, napi_value*);
typedef int (*CreateObjectFn)(napi_env, napi_value*);
typedef int (*SetNamedPropertyFn)(napi_env, napi_value, const char*, napi_value);
typedef int (*GetNamedPropertyFn)(napi_env, napi_value, const char*, napi_value*);
typedef int (*GetElementFn)(napi_env, napi_value, uint32_t, napi_value*);
typedef int (*SetElementFn)(napi_env, napi_value, uint32_t, napi_value);
typedef int (*CreateStringUtf8Fn)(napi_env, const char*, size_t, napi_value*);
typedef int (*GetArrayLengthFn)(napi_env, napi_value, uint32_t*);
typedef int (*GetValueUint32Fn)(napi_env, napi_value, uint32_t*);
typedef int (*GetValueInt32Fn)(napi_env, napi_value, int32_t*);
typedef int (*CreateUint32Fn)(napi_env, uint32_t, napi_value*);
typedef int (*CreateInt32Fn)(napi_env, int32_t, napi_value*);

typedef int (*IsBufferFn)(napi_env, napi_value, bool*);
typedef int (*GetBufferInfoFn)(napi_env, napi_value, void**, size_t*);
typedef int (*CreateBufferFn)(napi_env, void*, size_t, napi_value*, void**);
typedef int (*CreateArraybufferFn)(napi_env, size_t, void**, napi_value*);
typedef int (*GetArraybufferInfoFn)(napi_env, napi_value, void**, size_t*);

typedef int (*GetTypedarrayInfoFn)(napi_env, int, napi_value, size_t*, void**, void**, size_t*);
typedef int (*IsTypedarrayFn)(napi_env, napi_value, bool*);

typedef void (*ThrowErrorFn)(napi_env, const char*, const char*);
typedef napi_value (*GetUndefinedFn)(napi_env);
typedef struct {
    const char* utf8name;
    napi_value name;
    napi_callback method;
    napi_callback getter;
    napi_callback setter;
    int attributes;
    void* data;
} napi_property_descriptor;

typedef int (*DefinePropertiesFn)(napi_env, napi_value, size_t, const napi_property_descriptor*);
typedef napi_value (*GetGlobalFn)(napi_env, napi_value*);
typedef napi_value (*GetUndefinedValueFn)(napi_env);

typedef int (*OpenHandleScopeFn)(napi_env, napi_handle_scope*);
typedef int (*CloseHandleScopeFn)(napi_env, napi_handle_scope);

struct NapiApi {
    CreateFunctionFn createFunction = nullptr;
    GetCbInfoFn getCbInfo = nullptr;
    GetValueStringUtf8Fn getValueStringUtf8 = nullptr;
    TypeofFn typeOf = nullptr;
    CreateArrayFn createArray = nullptr;
    CreateObjectFn createObject = nullptr;
    SetNamedPropertyFn setNamedProperty = nullptr;
    GetNamedPropertyFn getNamedProperty = nullptr;
    GetElementFn getElement = nullptr;
    SetElementFn setElement = nullptr;
    CreateStringUtf8Fn createStringUtf8 = nullptr;
    GetArrayLengthFn getArrayLength = nullptr;
    GetValueUint32Fn getValueUint32 = nullptr;
    GetValueInt32Fn getValueInt32 = nullptr;
    CreateUint32Fn createUint32 = nullptr;
    CreateInt32Fn createInt32 = nullptr;
    IsBufferFn isBuffer = nullptr;
    GetBufferInfoFn getBufferInfo = nullptr;
    CreateBufferFn createBuffer = nullptr;
    IsTypedarrayFn isTypedarray = nullptr;
    GetTypedarrayInfoFn getTypedarrayInfo = nullptr;
    ThrowErrorFn throwError = nullptr;
    DefinePropertiesFn defineProperties = nullptr;
    OpenHandleScopeFn openHandleScope = nullptr;
    CloseHandleScopeFn closeHandleScope = nullptr;
};

NapiApi g_api;
std::atomic<int> g_apiState{0};

void* ResolveSymbol(const char* name) {
    void* handle = dlopen(nullptr, RTLD_NOW | RTLD_GLOBAL);
    if (handle == nullptr) {
        return nullptr;
    }
    return dlsym(handle, name);
}

bool LoadNapiApi() {
    if (g_apiState.load() == 2) {
        return true;
    }
    if (g_apiState.load() == 1) {
        return false;
    }
    g_apiState.store(1);

#define NEXUS_BIND(field, symbol) \
    g_api.field = reinterpret_cast<decltype(g_api.field)>(ResolveSymbol(symbol)); \
    if (g_api.field == nullptr) { return false; }

    NEXUS_BIND(createFunction, "napi_create_function")
    NEXUS_BIND(getCbInfo, "napi_get_cb_info")
    NEXUS_BIND(getValueStringUtf8, "napi_get_value_string_utf8")
    NEXUS_BIND(typeOf, "napi_typeof")
    NEXUS_BIND(createArray, "napi_create_array")
    NEXUS_BIND(createObject, "napi_create_object")
    NEXUS_BIND(setNamedProperty, "napi_set_named_property")
    NEXUS_BIND(getNamedProperty, "napi_get_named_property")
    NEXUS_BIND(getElement, "napi_get_element")
    NEXUS_BIND(setElement, "napi_set_element")
    NEXUS_BIND(createStringUtf8, "napi_create_string_utf8")
    NEXUS_BIND(getArrayLength, "napi_get_array_length")
    NEXUS_BIND(getValueUint32, "napi_get_value_uint32")
    NEXUS_BIND(getValueInt32, "napi_get_value_int32")
    NEXUS_BIND(createUint32, "napi_create_uint32")
    NEXUS_BIND(createInt32, "napi_create_int32")
    NEXUS_BIND(isBuffer, "napi_is_buffer")
    NEXUS_BIND(getBufferInfo, "napi_get_buffer_info")
    NEXUS_BIND(createBuffer, "napi_create_buffer")
    NEXUS_BIND(isTypedarray, "napi_is_typedarray")
    NEXUS_BIND(getTypedarrayInfo, "napi_get_typedarray_info")
    NEXUS_BIND(throwError, "napi_throw_error")
    NEXUS_BIND(defineProperties, "napi_define_properties")
    NEXUS_BIND(openHandleScope, "napi_open_handle_scope")
    NEXUS_BIND(closeHandleScope, "napi_close_handle_scope")

#undef NEXUS_BIND

    g_apiState.store(2);
    return true;
}



CreateFunctionFn g_origCreateFunction = nullptr;
std::atomic<int> g_hookedCount{0};
std::mutex g_nameMutex;

struct CapturedTarget {
    std::string name;
    napi_callback original;
};
std::vector<CapturedTarget> g_captured;

const char* const kInterestingNames[] = {
    "SendSSORequestInternal",
    "SendSSORequest",
    "SendRequest",
    "LoginRequest",
    "RecvPacket",
    "SendPacket",
};

bool IsInterestingName(const char* name, size_t length) {
    if (name == nullptr || length == 0) {
        return false;
    }
    for (const char* candidate : kInterestingNames) {
        const size_t candidateLength = std::strlen(candidate);
        if (candidateLength == length && std::memcmp(name, candidate, length) == 0) {
            return true;
        }
    }
    return false;
}

void LogLine(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    std::vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    const int fd = ::open("/tmp/nexuslab-napi-hook.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd >= 0) {
        ::write(fd, buffer, std::strlen(buffer));
        ::write(fd, "\n", 1);
        ::close(fd);
    }
}

DefinePropertiesFn g_origDefineProperties = nullptr;

napi_value CaptureReplacement(napi_env env, napi_callback_info info) {
    return nullptr;
}

int HookedDefineProperties(napi_env env, napi_value object, size_t count,
                           const napi_property_descriptor* descriptors) {
    LogLine("[napi-hook] define_properties called count=%zu descriptors=%p",
            count, reinterpret_cast<const void*>(descriptors));
    if (g_origDefineProperties == nullptr) {
        return 1;
    }
    return g_origDefineProperties(env, object, count, descriptors);
}

napi_value HookedCreateFunction(napi_env env, const char* utf8name, size_t length,
                                napi_callback callback, void* data, napi_value* result) {
    if (g_origCreateFunction == nullptr) {
        return nullptr;
    }
    if (utf8name != nullptr && IsInterestingName(utf8name, length)) {
        std::lock_guard<std::mutex> guard(g_nameMutex);
        CapturedTarget target;
        target.name.assign(utf8name, length);
        target.original = callback;
        g_captured.push_back(target);
        g_hookedCount.fetch_add(1);
        LogLine("[napi-hook] captured %.*s callback=%p data=%p",
                static_cast<int>(length), utf8name,
                reinterpret_cast<void*>(callback), data);
    }
    return g_origCreateFunction(env, utf8name, length, callback, data, result);
}

}  // namespace

void InstallNapiHooks() {
    if (!LoadNapiApi()) {
        LogLine("[napi-hook] LoadNapiApi failed");
        return;
    }
    LogLine("[napi-hook] napi api resolved; createFunction=%p",
            reinterpret_cast<void*>(g_api.createFunction));

    void* trampoline = nullptr;
    void* target = reinterpret_cast<void*>(g_api.createFunction);
    if (!nexuslab_inline::Install(target, reinterpret_cast<void*>(&HookedCreateFunction), &trampoline)) {
        LogLine("[napi-hook] inline hook on napi_create_function FAILED");
        return;
    }
    g_origCreateFunction = reinterpret_cast<CreateFunctionFn>(trampoline);
    LogLine("[napi-hook] napi_create_function hooked; trampoline=%p", trampoline);

    if (g_api.defineProperties != nullptr) {
        void* propsTrampoline = nullptr;
        if (nexuslab_inline::Install(reinterpret_cast<void*>(g_api.defineProperties),
                                     reinterpret_cast<void*>(&HookedDefineProperties),
                                     &propsTrampoline)) {
            g_origDefineProperties = reinterpret_cast<DefinePropertiesFn>(propsTrampoline);
            LogLine("[napi-hook] napi_define_properties hooked; trampoline=%p", propsTrampoline);
        } else {
            LogLine("[napi-hook] inline hook on napi_define_properties FAILED");
        }
    }
}

void ShutdownNapiHooks() {
    nexuslab_inline::RemoveAll();
}

int HookedFunctionCount() {
    return g_hookedCount.load();
}

}  // namespace nexuslab_napi
