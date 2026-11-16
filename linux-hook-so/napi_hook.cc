#include "napi_hook.h"
#include "inline_hook.h"
extern "C" int nexuslab_linux_hook_start_dynamic(const char* runtimeDir);

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
#include <new>

extern "C" {
int nexuslab_linux_hook_take_send(char* cmdBuf, size_t cmdCap, void* bodyBuf, size_t bodyCap, uint32_t* requestId, uint32_t* flags, size_t* bodyLenOut, int timeoutMs);
int nexuslab_linux_hook_send_reply(uint32_t requestId, int32_t status, const void* body, uint32_t bodyLen);
}
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

typedef int (*CreateFunctionFn)(napi_env, const char*, size_t, napi_callback, void*, napi_value*);
typedef struct napi_threadsafe_function__* napi_threadsafe_function;
typedef struct napi_ref__* napi_ref_t;
typedef void (*ThreadsafeCallJsFn)(napi_env, napi_value, void*, void*);
typedef int (*CreateThreadsafeFn)(napi_env, napi_value, napi_value, napi_value, size_t, size_t, void*, void*, void*, ThreadsafeCallJsFn, napi_threadsafe_function*);
typedef int (*ReleaseThreadsafeFn)(napi_threadsafe_function, int);
typedef int (*CallThreadsafeFn)(napi_threadsafe_function, void*, int);
typedef int (*CreateReferenceFn)(napi_env, napi_value, uint32_t, napi_ref_t*);
typedef int (*GetReferenceValueFn)(napi_env, napi_ref_t, napi_value*);
typedef int (*GetGlobalFnT)(napi_env, napi_value*);
typedef int (*CallFunctionFn)(napi_env, napi_value, napi_value, size_t, const napi_value*, napi_value*);
typedef int (*CreateBufferCopyFn)(napi_env, size_t, const void*, void**, napi_value*);
constexpr size_t NAPI_AUTO_LENGTH = static_cast<size_t>(-1);
typedef int (*GetValueDoubleFnT)(napi_env, napi_value, double*);
typedef int (*GetValueBoolFn)(napi_env, napi_value, bool*);
typedef int (*GetPropertyNamesFn)(napi_env, napi_value, napi_value*);
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
typedef int (*IsPromiseFn)(napi_env, napi_value, bool*);
typedef int (*GetLastExceptionFn)(napi_env, napi_value*);
typedef int (*CoerceToStringFn)(napi_env, napi_value, napi_value*);
typedef int (*GetUndefinedFn)(napi_env, napi_value*);
typedef struct {
    const char* utf8name;
    napi_value name;
    napi_callback method;
    napi_callback getter;
    napi_callback setter;
    napi_value value;
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
    CreateThreadsafeFn createThreadsafe = nullptr;
    CallThreadsafeFn callThreadsafe = nullptr;
    ReleaseThreadsafeFn releaseThreadsafe = nullptr;
    CreateReferenceFn createReference = nullptr;
    GetReferenceValueFn getReferenceValue = nullptr;
    GetGlobalFnT getGlobal = nullptr;
    CallFunctionFn callFunction = nullptr;
    CreateBufferCopyFn createBufferCopy = nullptr;
    GetUndefinedFn getUndefined = nullptr;
    GetPropertyNamesFn getPropertyNames = nullptr;
    GetValueDoubleFnT getValueDoubleFn = nullptr;
    GetValueBoolFn getValueBool = nullptr;
    GetLastExceptionFn getLastException = nullptr;
    CoerceToStringFn coerceToString = nullptr;
    IsPromiseFn isPromise = nullptr;
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
    NEXUS_BIND(createThreadsafe, "napi_create_threadsafe_function")
    NEXUS_BIND(callThreadsafe, "napi_call_threadsafe_function")
    NEXUS_BIND(releaseThreadsafe, "napi_release_threadsafe_function")
    NEXUS_BIND(createReference, "napi_create_reference")
    NEXUS_BIND(getReferenceValue, "napi_get_reference_value")
    NEXUS_BIND(getGlobal, "napi_get_global")
    NEXUS_BIND(callFunction, "napi_call_function")
    NEXUS_BIND(createBufferCopy, "napi_create_buffer_copy")
    NEXUS_BIND(getUndefined, "napi_get_undefined")
    NEXUS_BIND(getPropertyNames, "napi_get_property_names")
    NEXUS_BIND(getValueDoubleFn, "napi_get_value_double")
    NEXUS_BIND(getLastException, "napi_get_and_clear_last_exception")
    NEXUS_BIND(coerceToString, "napi_coerce_to_string")
    NEXUS_BIND(isPromise, "napi_is_promise")
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

struct SendBridgeRequest {
    uint32_t requestId;
    char cmd[256];
    std::string body;
};

void ReplyWithObjectKeys(napi_env env, uint32_t requestId, napi_value obj) {
    char buf[2048];
    size_t off = 0;
    buf[0] = 0;
    if (obj != nullptr && g_api.getPropertyNames != nullptr) {
        napi_value names = nullptr;
        if (g_api.getPropertyNames(env, obj, &names) == 0 && names != nullptr) {
            uint32_t len = 0;
            g_api.getArrayLength(env, names, &len);
            for (uint32_t i = 0; i < len && off + 200 < sizeof(buf); ++i) {
                napi_value item = nullptr;
                g_api.getElement(env, names, i, &item);
                if (item == nullptr) {
                    continue;
                }
                char nm[120];
                nm[0] = 0;
                size_t n = 0;
                g_api.getValueStringUtf8(env, item, nm, sizeof(nm) - 1, &n);
                off += static_cast<size_t>(snprintf(buf + off, sizeof(buf) - off - 1, "%s;", nm));
            }
        }
    }
    LogLine("[bridge] keys reqId=%u keys=%s", requestId, buf);
    nexuslab_linux_hook_send_reply(requestId, 0, buf, static_cast<uint32_t>(off));
}

void ReplyWithException(napi_env env, uint32_t requestId) {
    char text[1024];
    text[0] = 0;
    size_t len = 0;
    if (g_api.getLastException != nullptr) {
        napi_value exc = nullptr;
        if (g_api.getLastException(env, &exc) == 0 && exc != nullptr) {
            napi_value asString = nullptr;
            if (g_api.coerceToString != nullptr && g_api.coerceToString(env, exc, &asString) == 0 && asString != nullptr) {
                g_api.getValueStringUtf8(env, asString, text, sizeof(text) - 1, &len);
            }
        }
    }
    LogLine("[bridge] js exception reqId=%u text=%s", requestId, text);
    nexuslab_linux_hook_send_reply(requestId, -6, text, static_cast<uint32_t>(len));
}

void ReplyWithValue(napi_env env, uint32_t requestId, napi_value value, int32_t status) {
    char buf[1024];
    buf[0] = 0;
    size_t len = 0;
    if (value != nullptr && g_api.getValueStringUtf8 != nullptr) {
        g_api.getValueStringUtf8(env, value, buf, sizeof(buf) - 1, &len);
    }
    LogLine("[bridge] reply reqId=%u status=%d body=%s", requestId, status, buf);
    nexuslab_linux_hook_send_reply(requestId, status, buf, static_cast<uint32_t>(len));
}

napi_value PromiseThenHandler(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    void* data = nullptr;
    g_api.getCbInfo(env, info, &argc, argv, nullptr, &data);
    const uint32_t requestId = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(data));
    napi_value value = argc > 0 ? argv[0] : nullptr;
    ReplyWithValue(env, requestId, value, 0);
    return nullptr;
}
std::atomic<napi_threadsafe_function> g_sendTsfn{nullptr};
napi_ref_t g_exportsRef = nullptr;
std::atomic<bool> g_bridgeAlive{false};

napi_value NewBridgeJsCallback(napi_env env, napi_callback_info info) {
    return nullptr;
}

void ShutdownTsfn() {
    napi_threadsafe_function tsfn = g_sendTsfn.exchange(nullptr);
    if (tsfn != nullptr && g_api.releaseThreadsafe != nullptr) {
        g_api.releaseThreadsafe(tsfn, 1);
    }
}

void BridgeCallJs(napi_env env, napi_value jsCb, void* context, void* data) {
    SendBridgeRequest* req = static_cast<SendBridgeRequest*>(data);
    if (req == nullptr) {
        return;
    }
    LogLine("[bridge] dispatch cmd=%s reqId=%u", req->cmd, req->requestId);
    if (g_api.getReferenceValue == nullptr || g_api.callFunction == nullptr) {
        LogLine("[bridge] api missing");
        delete req;
        return;
    }
    napi_value exports = nullptr;
    if (g_exportsRef == nullptr || g_api.getReferenceValue(env, g_exportsRef, &exports) != 0 || exports == nullptr) {
        LogLine("[bridge] exports ref invalid");
        delete req;
        return;
    }
    napi_value undefined = nullptr;
    if (g_api.getUndefined != nullptr) {
        g_api.getUndefined(env, &undefined);
    }
    napi_value argv[2];
    argv[0] = nullptr;
    argv[1] = nullptr;
    g_api.createStringUtf8(env, req->cmd, NAPI_AUTO_LENGTH, &argv[0]);
    if (argv[0] == nullptr) {
        LogLine("[bridge] cmd string failed");
        delete req;
        return;
    }
    if (g_api.createBufferCopy != nullptr && !req->body.empty()) {
        g_api.createBufferCopy(env, req->body.size(), req->body.data(), nullptr, &argv[1]);
    }
    napi_value target = nullptr;
    if (g_api.getNamedProperty == nullptr) {
        LogLine("[bridge] getNamedProperty missing");
        nexuslab_linux_hook_send_reply(req->requestId, -7, "", 0);
        delete req;
        return;
    }
    napi_value factory = nullptr;
    const int factRc = g_api.getNamedProperty(env, exports, "getNTWrapperSession", &factory);
    LogLine("[bridge] factory rc=%d fn=%p", factRc, reinterpret_cast<void*>(factory));
    napi_value session = nullptr;
    if (factRc == 0 && factory != nullptr) {
        napi_value sid = nullptr;
        g_api.createStringUtf8(env, "nt_1", NAPI_AUTO_LENGTH, &sid);
        napi_value undef = nullptr;
        g_api.getUndefined(env, &undef);
        const int sessRc = g_api.callFunction(env, exports, factory, sid != nullptr ? 1 : 0, &sid, &session);
        LogLine("[bridge] session rc=%d obj=%p", sessRc, reinterpret_cast<void*>(session));
        if (sessRc != 0) {
            ReplyWithException(env, req->requestId);
            delete req;
            return;
        }
        ReplyWithObjectKeys(env, req->requestId + 100000, session);
    }
    if (session != nullptr) {
        const int propRc = g_api.getNamedProperty(env, session, "sendSSORequest", &target);
        LogLine("[bridge] sso prop rc=%d fn=%p", propRc, reinterpret_cast<void*>(target));
        if (propRc != 0 || target == nullptr) {
            nexuslab_linux_hook_send_reply(req->requestId, -3, "", 0);
            delete req;
            return;
        }
    } else {
        const int propRc = g_api.getNamedProperty(env, exports, "SendSSORequestInternal", &target);
        if (propRc != 0 || target == nullptr) {
            LogLine("[bridge] target property missing rc=%d", propRc);
            nexuslab_linux_hook_send_reply(req->requestId, -3, "", 0);
            delete req;
            return;
        }
    }
    int32_t arity = 2;
    napi_value arityValue = nullptr;
    if (g_api.getNamedProperty(env, target, "length", &arityValue) == 0 && arityValue != nullptr) {
        int32_t parsed = 0;
        if (g_api.getValueInt32(env, arityValue, &parsed) == 0 && parsed >= 1 && parsed <= 3) {
            arity = parsed;
        }
    }
    LogLine("[bridge] target arity=%d", arity);
    napi_value callArgs[3];
    size_t callArgc = 0;
    if (arity >= 1) {
        napi_value cmdValue = nullptr;
        if (g_api.createStringUtf8(env, req->cmd, NAPI_AUTO_LENGTH, &cmdValue) != 0 || cmdValue == nullptr) {
            LogLine("[bridge] cmd string failed");
            nexuslab_linux_hook_send_reply(req->requestId, -3, "", 0);
            delete req;
            return;
        }
        callArgs[callArgc++] = cmdValue;
    }
    if (arity >= 2) {
        napi_value bodyValue = nullptr;
        if (g_api.createBufferCopy != nullptr) {
            g_api.createBufferCopy(env, req->body.size(), req->body.empty() ? "" : req->body.data(), nullptr, &bodyValue);
        }
        callArgs[callArgc++] = bodyValue != nullptr ? bodyValue : undefined;
    }
    if (arity >= 3) {
        callArgs[callArgc++] = undefined;
    }
    napi_value result = nullptr;
    const int rc = g_api.callFunction(env, exports, target, callArgc, callArgs, &result);
    LogLine("[bridge] call rc=%d argc=%zu", rc, callArgc);
    if (rc != 0) {
        LogLine("[bridge] call failed rc=%d argc=%zu", rc, callArgc);
        ReplyWithException(env, req->requestId);
        delete req;
        return;
    }
    bool isPromise = false;
    if (g_api.isPromise != nullptr && result != nullptr) {
        g_api.isPromise(env, result, &isPromise);
    }
    if (!isPromise && result != nullptr) {
        napi_value typeProbe = nullptr;
        napi_value thenProbe = nullptr;
        if (g_api.getNamedProperty(env, result, "then", &thenProbe) == 0 && thenProbe != nullptr) {
            int32_t thenType = -1;
            if (g_api.typeOf != nullptr && g_api.typeOf(env, thenProbe, &thenType) == 0 && thenType == 7) {
                isPromise = true;
            }
        }
        (void)typeProbe;
    }
    LogLine("[bridge] isPromise=%d result=%p", isPromise ? 1 : 0, reinterpret_cast<void*>(result));
    if (isPromise) {
        LogLine("[bridge] promise detected, attaching then");
        napi_value thenFn = nullptr;
        napi_value handler = nullptr;
        const int thenRc = g_api.getNamedProperty(env, result, "then", &thenFn);
        LogLine("[bridge] then lookup rc=%d fn=%p", thenRc, reinterpret_cast<void*>(thenFn));
        int fnRc = -1;
        if (thenRc == 0 && thenFn != nullptr) {
            fnRc = g_api.createFunction(env, "nexuslabThen", NAPI_AUTO_LENGTH, &PromiseThenHandler,
                                        reinterpret_cast<void*>(static_cast<uintptr_t>(req->requestId)), &handler);
            LogLine("[bridge] handler create rc=%d handler=%p", fnRc, reinterpret_cast<void*>(handler));
        }
        if (thenRc == 0 && thenFn != nullptr && fnRc == 0 && handler != nullptr) {
            napi_value chained = nullptr;
            const int chainRc = g_api.callFunction(env, result, thenFn, 1, &handler, &chained);
            LogLine("[bridge] then attached rc=%d", chainRc);
        } else {
            LogLine("[bridge] then attach failed");
            nexuslab_linux_hook_send_reply(req->requestId, -5, "", 0);
        }
    } else {
        ReplyWithValue(env, req->requestId, result, 0);
    }
    delete req;
}
constexpr int kMaxCaptureSlots = 512;



struct CaptureSlot {
    napi_callback original;
    void* userData;
    const char* batchFirst;
    size_t index;
    std::atomic<int> calls;
};

CaptureSlot g_captureTable[kMaxCaptureSlots];
std::atomic<int> g_captureSlots{0};

CaptureSlot* FindSlotByOriginal(void* original) {
    for (int i = 0; i < g_captureSlots.load(); ++i) {
        if (reinterpret_cast<void*>(g_captureTable[i].original) == original) {
            return &g_captureTable[i];
        }
    }
    return nullptr;
}

std::atomic<int> g_argDumpCount{0};

void DumpCallArgs(napi_env env, napi_callback_info info) {
    if (g_argDumpCount.load() >= 20) {
        return;
    }
    const int seq = g_argDumpCount.fetch_add(1);
    if (g_api.getCbInfo == nullptr || g_api.typeOf == nullptr) {
        return;
    }
    size_t argc = 8;
    napi_value argv[8];
    g_api.getCbInfo(env, info, &argc, argv, nullptr, nullptr);
    LogLine("[args] seq=%d argc=%zu", seq, argc);
    for (size_t i = 0; i < argc && i < 8; ++i) {
        int32_t t = -1;
        g_api.typeOf(env, argv[i], &t);
        if (t == 4) {
            char s[512];
            s[0] = 0;
            size_t n = 0;
            g_api.getValueStringUtf8(env, argv[i], s, sizeof(s) - 1, &n);
            LogLine("[args]   [%zu] string=%s", i, s);
        } else if (t == 3) {
            double d = 0;
            g_api.getValueDoubleFn(env, argv[i], &d);
            LogLine("[args]   [%zu] number=%f", i, d);
        } else if (t == 9) {
            bool b = false;
            g_api.getValueBool(env, argv[i], &b);
            LogLine("[args]   [%zu] boolean=%d", i, b ? 1 : 0);
        } else {
            LogLine("[args]   [%zu] type=%d", i, t);
        }
    }
}
napi_value ProxyDispatchBySlot(int slotIndex, napi_env env, napi_callback_info info) {
    if (slotIndex < 0 || slotIndex >= kMaxCaptureSlots) {
        return nullptr;
    }
    CaptureSlot& slot = g_captureTable[slotIndex];
    napi_callback original = slot.original;
    if (original == nullptr) {
        return nullptr;
    }
    DumpCallArgs(env, info);
    slot.calls.fetch_add(1);
    LogLine("[proxy] slot#%d batch=%s idx=%zu fn=%p calls=%d",
            slotIndex, slot.batchFirst, slot.index,
            reinterpret_cast<void*>(original), slot.calls.load());
    return original(env, info);
}

template <int N>
napi_value ProxyDispatchN(napi_env env, napi_callback_info info) {
    return ProxyDispatchBySlot(N, env, info);
}

const napi_callback kProxyTable[512] = {
    ProxyDispatchN<0>,
    ProxyDispatchN<1>,
    ProxyDispatchN<2>,
    ProxyDispatchN<3>,
    ProxyDispatchN<4>,
    ProxyDispatchN<5>,
    ProxyDispatchN<6>,
    ProxyDispatchN<7>,
    ProxyDispatchN<8>,
    ProxyDispatchN<9>,
    ProxyDispatchN<10>,
    ProxyDispatchN<11>,
    ProxyDispatchN<12>,
    ProxyDispatchN<13>,
    ProxyDispatchN<14>,
    ProxyDispatchN<15>,
    ProxyDispatchN<16>,
    ProxyDispatchN<17>,
    ProxyDispatchN<18>,
    ProxyDispatchN<19>,
    ProxyDispatchN<20>,
    ProxyDispatchN<21>,
    ProxyDispatchN<22>,
    ProxyDispatchN<23>,
    ProxyDispatchN<24>,
    ProxyDispatchN<25>,
    ProxyDispatchN<26>,
    ProxyDispatchN<27>,
    ProxyDispatchN<28>,
    ProxyDispatchN<29>,
    ProxyDispatchN<30>,
    ProxyDispatchN<31>,
    ProxyDispatchN<32>,
    ProxyDispatchN<33>,
    ProxyDispatchN<34>,
    ProxyDispatchN<35>,
    ProxyDispatchN<36>,
    ProxyDispatchN<37>,
    ProxyDispatchN<38>,
    ProxyDispatchN<39>,
    ProxyDispatchN<40>,
    ProxyDispatchN<41>,
    ProxyDispatchN<42>,
    ProxyDispatchN<43>,
    ProxyDispatchN<44>,
    ProxyDispatchN<45>,
    ProxyDispatchN<46>,
    ProxyDispatchN<47>,
    ProxyDispatchN<48>,
    ProxyDispatchN<49>,
    ProxyDispatchN<50>,
    ProxyDispatchN<51>,
    ProxyDispatchN<52>,
    ProxyDispatchN<53>,
    ProxyDispatchN<54>,
    ProxyDispatchN<55>,
    ProxyDispatchN<56>,
    ProxyDispatchN<57>,
    ProxyDispatchN<58>,
    ProxyDispatchN<59>,
    ProxyDispatchN<60>,
    ProxyDispatchN<61>,
    ProxyDispatchN<62>,
    ProxyDispatchN<63>,
    ProxyDispatchN<64>,
    ProxyDispatchN<65>,
    ProxyDispatchN<66>,
    ProxyDispatchN<67>,
    ProxyDispatchN<68>,
    ProxyDispatchN<69>,
    ProxyDispatchN<70>,
    ProxyDispatchN<71>,
    ProxyDispatchN<72>,
    ProxyDispatchN<73>,
    ProxyDispatchN<74>,
    ProxyDispatchN<75>,
    ProxyDispatchN<76>,
    ProxyDispatchN<77>,
    ProxyDispatchN<78>,
    ProxyDispatchN<79>,
    ProxyDispatchN<80>,
    ProxyDispatchN<81>,
    ProxyDispatchN<82>,
    ProxyDispatchN<83>,
    ProxyDispatchN<84>,
    ProxyDispatchN<85>,
    ProxyDispatchN<86>,
    ProxyDispatchN<87>,
    ProxyDispatchN<88>,
    ProxyDispatchN<89>,
    ProxyDispatchN<90>,
    ProxyDispatchN<91>,
    ProxyDispatchN<92>,
    ProxyDispatchN<93>,
    ProxyDispatchN<94>,
    ProxyDispatchN<95>,
    ProxyDispatchN<96>,
    ProxyDispatchN<97>,
    ProxyDispatchN<98>,
    ProxyDispatchN<99>,
    ProxyDispatchN<100>,
    ProxyDispatchN<101>,
    ProxyDispatchN<102>,
    ProxyDispatchN<103>,
    ProxyDispatchN<104>,
    ProxyDispatchN<105>,
    ProxyDispatchN<106>,
    ProxyDispatchN<107>,
    ProxyDispatchN<108>,
    ProxyDispatchN<109>,
    ProxyDispatchN<110>,
    ProxyDispatchN<111>,
    ProxyDispatchN<112>,
    ProxyDispatchN<113>,
    ProxyDispatchN<114>,
    ProxyDispatchN<115>,
    ProxyDispatchN<116>,
    ProxyDispatchN<117>,
    ProxyDispatchN<118>,
    ProxyDispatchN<119>,
    ProxyDispatchN<120>,
    ProxyDispatchN<121>,
    ProxyDispatchN<122>,
    ProxyDispatchN<123>,
    ProxyDispatchN<124>,
    ProxyDispatchN<125>,
    ProxyDispatchN<126>,
    ProxyDispatchN<127>,
    ProxyDispatchN<128>,
    ProxyDispatchN<129>,
    ProxyDispatchN<130>,
    ProxyDispatchN<131>,
    ProxyDispatchN<132>,
    ProxyDispatchN<133>,
    ProxyDispatchN<134>,
    ProxyDispatchN<135>,
    ProxyDispatchN<136>,
    ProxyDispatchN<137>,
    ProxyDispatchN<138>,
    ProxyDispatchN<139>,
    ProxyDispatchN<140>,
    ProxyDispatchN<141>,
    ProxyDispatchN<142>,
    ProxyDispatchN<143>,
    ProxyDispatchN<144>,
    ProxyDispatchN<145>,
    ProxyDispatchN<146>,
    ProxyDispatchN<147>,
    ProxyDispatchN<148>,
    ProxyDispatchN<149>,
    ProxyDispatchN<150>,
    ProxyDispatchN<151>,
    ProxyDispatchN<152>,
    ProxyDispatchN<153>,
    ProxyDispatchN<154>,
    ProxyDispatchN<155>,
    ProxyDispatchN<156>,
    ProxyDispatchN<157>,
    ProxyDispatchN<158>,
    ProxyDispatchN<159>,
    ProxyDispatchN<160>,
    ProxyDispatchN<161>,
    ProxyDispatchN<162>,
    ProxyDispatchN<163>,
    ProxyDispatchN<164>,
    ProxyDispatchN<165>,
    ProxyDispatchN<166>,
    ProxyDispatchN<167>,
    ProxyDispatchN<168>,
    ProxyDispatchN<169>,
    ProxyDispatchN<170>,
    ProxyDispatchN<171>,
    ProxyDispatchN<172>,
    ProxyDispatchN<173>,
    ProxyDispatchN<174>,
    ProxyDispatchN<175>,
    ProxyDispatchN<176>,
    ProxyDispatchN<177>,
    ProxyDispatchN<178>,
    ProxyDispatchN<179>,
    ProxyDispatchN<180>,
    ProxyDispatchN<181>,
    ProxyDispatchN<182>,
    ProxyDispatchN<183>,
    ProxyDispatchN<184>,
    ProxyDispatchN<185>,
    ProxyDispatchN<186>,
    ProxyDispatchN<187>,
    ProxyDispatchN<188>,
    ProxyDispatchN<189>,
    ProxyDispatchN<190>,
    ProxyDispatchN<191>,
    ProxyDispatchN<192>,
    ProxyDispatchN<193>,
    ProxyDispatchN<194>,
    ProxyDispatchN<195>,
    ProxyDispatchN<196>,
    ProxyDispatchN<197>,
    ProxyDispatchN<198>,
    ProxyDispatchN<199>,
    ProxyDispatchN<200>,
    ProxyDispatchN<201>,
    ProxyDispatchN<202>,
    ProxyDispatchN<203>,
    ProxyDispatchN<204>,
    ProxyDispatchN<205>,
    ProxyDispatchN<206>,
    ProxyDispatchN<207>,
    ProxyDispatchN<208>,
    ProxyDispatchN<209>,
    ProxyDispatchN<210>,
    ProxyDispatchN<211>,
    ProxyDispatchN<212>,
    ProxyDispatchN<213>,
    ProxyDispatchN<214>,
    ProxyDispatchN<215>,
    ProxyDispatchN<216>,
    ProxyDispatchN<217>,
    ProxyDispatchN<218>,
    ProxyDispatchN<219>,
    ProxyDispatchN<220>,
    ProxyDispatchN<221>,
    ProxyDispatchN<222>,
    ProxyDispatchN<223>,
    ProxyDispatchN<224>,
    ProxyDispatchN<225>,
    ProxyDispatchN<226>,
    ProxyDispatchN<227>,
    ProxyDispatchN<228>,
    ProxyDispatchN<229>,
    ProxyDispatchN<230>,
    ProxyDispatchN<231>,
    ProxyDispatchN<232>,
    ProxyDispatchN<233>,
    ProxyDispatchN<234>,
    ProxyDispatchN<235>,
    ProxyDispatchN<236>,
    ProxyDispatchN<237>,
    ProxyDispatchN<238>,
    ProxyDispatchN<239>,
    ProxyDispatchN<240>,
    ProxyDispatchN<241>,
    ProxyDispatchN<242>,
    ProxyDispatchN<243>,
    ProxyDispatchN<244>,
    ProxyDispatchN<245>,
    ProxyDispatchN<246>,
    ProxyDispatchN<247>,
    ProxyDispatchN<248>,
    ProxyDispatchN<249>,
    ProxyDispatchN<250>,
    ProxyDispatchN<251>,
    ProxyDispatchN<252>,
    ProxyDispatchN<253>,
    ProxyDispatchN<254>,
    ProxyDispatchN<255>,
    ProxyDispatchN<256>,
    ProxyDispatchN<257>,
    ProxyDispatchN<258>,
    ProxyDispatchN<259>,
    ProxyDispatchN<260>,
    ProxyDispatchN<261>,
    ProxyDispatchN<262>,
    ProxyDispatchN<263>,
    ProxyDispatchN<264>,
    ProxyDispatchN<265>,
    ProxyDispatchN<266>,
    ProxyDispatchN<267>,
    ProxyDispatchN<268>,
    ProxyDispatchN<269>,
    ProxyDispatchN<270>,
    ProxyDispatchN<271>,
    ProxyDispatchN<272>,
    ProxyDispatchN<273>,
    ProxyDispatchN<274>,
    ProxyDispatchN<275>,
    ProxyDispatchN<276>,
    ProxyDispatchN<277>,
    ProxyDispatchN<278>,
    ProxyDispatchN<279>,
    ProxyDispatchN<280>,
    ProxyDispatchN<281>,
    ProxyDispatchN<282>,
    ProxyDispatchN<283>,
    ProxyDispatchN<284>,
    ProxyDispatchN<285>,
    ProxyDispatchN<286>,
    ProxyDispatchN<287>,
    ProxyDispatchN<288>,
    ProxyDispatchN<289>,
    ProxyDispatchN<290>,
    ProxyDispatchN<291>,
    ProxyDispatchN<292>,
    ProxyDispatchN<293>,
    ProxyDispatchN<294>,
    ProxyDispatchN<295>,
    ProxyDispatchN<296>,
    ProxyDispatchN<297>,
    ProxyDispatchN<298>,
    ProxyDispatchN<299>,
    ProxyDispatchN<300>,
    ProxyDispatchN<301>,
    ProxyDispatchN<302>,
    ProxyDispatchN<303>,
    ProxyDispatchN<304>,
    ProxyDispatchN<305>,
    ProxyDispatchN<306>,
    ProxyDispatchN<307>,
    ProxyDispatchN<308>,
    ProxyDispatchN<309>,
    ProxyDispatchN<310>,
    ProxyDispatchN<311>,
    ProxyDispatchN<312>,
    ProxyDispatchN<313>,
    ProxyDispatchN<314>,
    ProxyDispatchN<315>,
    ProxyDispatchN<316>,
    ProxyDispatchN<317>,
    ProxyDispatchN<318>,
    ProxyDispatchN<319>,
    ProxyDispatchN<320>,
    ProxyDispatchN<321>,
    ProxyDispatchN<322>,
    ProxyDispatchN<323>,
    ProxyDispatchN<324>,
    ProxyDispatchN<325>,
    ProxyDispatchN<326>,
    ProxyDispatchN<327>,
    ProxyDispatchN<328>,
    ProxyDispatchN<329>,
    ProxyDispatchN<330>,
    ProxyDispatchN<331>,
    ProxyDispatchN<332>,
    ProxyDispatchN<333>,
    ProxyDispatchN<334>,
    ProxyDispatchN<335>,
    ProxyDispatchN<336>,
    ProxyDispatchN<337>,
    ProxyDispatchN<338>,
    ProxyDispatchN<339>,
    ProxyDispatchN<340>,
    ProxyDispatchN<341>,
    ProxyDispatchN<342>,
    ProxyDispatchN<343>,
    ProxyDispatchN<344>,
    ProxyDispatchN<345>,
    ProxyDispatchN<346>,
    ProxyDispatchN<347>,
    ProxyDispatchN<348>,
    ProxyDispatchN<349>,
    ProxyDispatchN<350>,
    ProxyDispatchN<351>,
    ProxyDispatchN<352>,
    ProxyDispatchN<353>,
    ProxyDispatchN<354>,
    ProxyDispatchN<355>,
    ProxyDispatchN<356>,
    ProxyDispatchN<357>,
    ProxyDispatchN<358>,
    ProxyDispatchN<359>,
    ProxyDispatchN<360>,
    ProxyDispatchN<361>,
    ProxyDispatchN<362>,
    ProxyDispatchN<363>,
    ProxyDispatchN<364>,
    ProxyDispatchN<365>,
    ProxyDispatchN<366>,
    ProxyDispatchN<367>,
    ProxyDispatchN<368>,
    ProxyDispatchN<369>,
    ProxyDispatchN<370>,
    ProxyDispatchN<371>,
    ProxyDispatchN<372>,
    ProxyDispatchN<373>,
    ProxyDispatchN<374>,
    ProxyDispatchN<375>,
    ProxyDispatchN<376>,
    ProxyDispatchN<377>,
    ProxyDispatchN<378>,
    ProxyDispatchN<379>,
    ProxyDispatchN<380>,
    ProxyDispatchN<381>,
    ProxyDispatchN<382>,
    ProxyDispatchN<383>,
    ProxyDispatchN<384>,
    ProxyDispatchN<385>,
    ProxyDispatchN<386>,
    ProxyDispatchN<387>,
    ProxyDispatchN<388>,
    ProxyDispatchN<389>,
    ProxyDispatchN<390>,
    ProxyDispatchN<391>,
    ProxyDispatchN<392>,
    ProxyDispatchN<393>,
    ProxyDispatchN<394>,
    ProxyDispatchN<395>,
    ProxyDispatchN<396>,
    ProxyDispatchN<397>,
    ProxyDispatchN<398>,
    ProxyDispatchN<399>,
    ProxyDispatchN<400>,
    ProxyDispatchN<401>,
    ProxyDispatchN<402>,
    ProxyDispatchN<403>,
    ProxyDispatchN<404>,
    ProxyDispatchN<405>,
    ProxyDispatchN<406>,
    ProxyDispatchN<407>,
    ProxyDispatchN<408>,
    ProxyDispatchN<409>,
    ProxyDispatchN<410>,
    ProxyDispatchN<411>,
    ProxyDispatchN<412>,
    ProxyDispatchN<413>,
    ProxyDispatchN<414>,
    ProxyDispatchN<415>,
    ProxyDispatchN<416>,
    ProxyDispatchN<417>,
    ProxyDispatchN<418>,
    ProxyDispatchN<419>,
    ProxyDispatchN<420>,
    ProxyDispatchN<421>,
    ProxyDispatchN<422>,
    ProxyDispatchN<423>,
    ProxyDispatchN<424>,
    ProxyDispatchN<425>,
    ProxyDispatchN<426>,
    ProxyDispatchN<427>,
    ProxyDispatchN<428>,
    ProxyDispatchN<429>,
    ProxyDispatchN<430>,
    ProxyDispatchN<431>,
    ProxyDispatchN<432>,
    ProxyDispatchN<433>,
    ProxyDispatchN<434>,
    ProxyDispatchN<435>,
    ProxyDispatchN<436>,
    ProxyDispatchN<437>,
    ProxyDispatchN<438>,
    ProxyDispatchN<439>,
    ProxyDispatchN<440>,
    ProxyDispatchN<441>,
    ProxyDispatchN<442>,
    ProxyDispatchN<443>,
    ProxyDispatchN<444>,
    ProxyDispatchN<445>,
    ProxyDispatchN<446>,
    ProxyDispatchN<447>,
    ProxyDispatchN<448>,
    ProxyDispatchN<449>,
    ProxyDispatchN<450>,
    ProxyDispatchN<451>,
    ProxyDispatchN<452>,
    ProxyDispatchN<453>,
    ProxyDispatchN<454>,
    ProxyDispatchN<455>,
    ProxyDispatchN<456>,
    ProxyDispatchN<457>,
    ProxyDispatchN<458>,
    ProxyDispatchN<459>,
    ProxyDispatchN<460>,
    ProxyDispatchN<461>,
    ProxyDispatchN<462>,
    ProxyDispatchN<463>,
    ProxyDispatchN<464>,
    ProxyDispatchN<465>,
    ProxyDispatchN<466>,
    ProxyDispatchN<467>,
    ProxyDispatchN<468>,
    ProxyDispatchN<469>,
    ProxyDispatchN<470>,
    ProxyDispatchN<471>,
    ProxyDispatchN<472>,
    ProxyDispatchN<473>,
    ProxyDispatchN<474>,
    ProxyDispatchN<475>,
    ProxyDispatchN<476>,
    ProxyDispatchN<477>,
    ProxyDispatchN<478>,
    ProxyDispatchN<479>,
    ProxyDispatchN<480>,
    ProxyDispatchN<481>,
    ProxyDispatchN<482>,
    ProxyDispatchN<483>,
    ProxyDispatchN<484>,
    ProxyDispatchN<485>,
    ProxyDispatchN<486>,
    ProxyDispatchN<487>,
    ProxyDispatchN<488>,
    ProxyDispatchN<489>,
    ProxyDispatchN<490>,
    ProxyDispatchN<491>,
    ProxyDispatchN<492>,
    ProxyDispatchN<493>,
    ProxyDispatchN<494>,
    ProxyDispatchN<495>,
    ProxyDispatchN<496>,
    ProxyDispatchN<497>,
    ProxyDispatchN<498>,
    ProxyDispatchN<499>,
    ProxyDispatchN<500>,
    ProxyDispatchN<501>,
    ProxyDispatchN<502>,
    ProxyDispatchN<503>,
    ProxyDispatchN<504>,
    ProxyDispatchN<505>,
    ProxyDispatchN<506>,
    ProxyDispatchN<507>,
    ProxyDispatchN<508>,
    ProxyDispatchN<509>,
    ProxyDispatchN<510>,
    ProxyDispatchN<511>
};


int HookedDefineProperties(napi_env env, napi_value object, size_t count,
                           const napi_property_descriptor* descriptors) {
    if (g_origDefineProperties == nullptr) {
        return 1;
    }
    if (count >= 1 && count < 512 && descriptors != nullptr) {
        const char* first = descriptors[0].utf8name;
        LogLine("[napi-hook] batch count=%zu first=%s",
                count, (first != nullptr && reinterpret_cast<uintptr_t>(first) > 0x10000) ? first : "(napi_value)");
        if (g_exportsRef == nullptr && g_api.createReference != nullptr && g_api.createThreadsafe != nullptr && g_api.getUndefined != nullptr) {
            napi_ref_t ref = nullptr;
            if (g_api.createReference(env, object, 1, &ref) == 0 && ref != nullptr) {
                g_exportsRef = ref;
                napi_value undefined = nullptr;
                g_api.getUndefined(env, &undefined);
                napi_value jsFn = nullptr;
                g_api.createFunction(env, "nexuslabBridge", NAPI_AUTO_LENGTH, &NewBridgeJsCallback, nullptr, &jsFn);
                napi_threadsafe_function tsfn = nullptr;
                int rc = -1;
                if (jsFn != nullptr) {
                    napi_value resName = nullptr;
                    g_api.createStringUtf8(env, "nexuslab-bridge", NAPI_AUTO_LENGTH, &resName);
                    rc = g_api.createThreadsafe(env, jsFn, (napi_value)nullptr, resName, (size_t)0, (size_t)4, (void*)nullptr, (void*)nullptr, (void*)nullptr, &BridgeCallJs, &tsfn);
                }
                LogLine("[bridge] tsfn create rc=%d tsfn=%p", rc, reinterpret_cast<void*>(tsfn));
                if (rc == 0 && tsfn != nullptr) {
                    g_sendTsfn.store(tsfn);
                    g_bridgeAlive.store(true);
                    std::atexit(&ShutdownTsfn);
                }
            } else {
                LogLine("[bridge] reference create failed");
            }
        }
        if (g_captureSlots.load() < kMaxCaptureSlots) {
            napi_property_descriptor* writable = const_cast<napi_property_descriptor*>(descriptors);
            for (size_t i = 0; i < count && g_captureSlots.load() < kMaxCaptureSlots; ++i) {
                if (writable[i].method == nullptr) {
                    continue;
                }
                CaptureSlot& slot = g_captureTable[g_captureSlots.load()];
                slot.original = writable[i].method;
                slot.userData = writable[i].data;
                slot.batchFirst = (first != nullptr && reinterpret_cast<uintptr_t>(first) > 0x10000) ? first : "";
                slot.index = i;
                writable[i].method = g_captureSlots.load() < 512 ? kProxyTable[g_captureSlots.load()] : writable[i].method;
                g_captureSlots.fetch_add(1);
            }
            LogLine("[napi-hook] captured %d proxies so far", g_captureSlots.load());
        }
    }
    return g_origDefineProperties(env, object, count, descriptors);
}

int HookedCreateFunction(napi_env env, const char* utf8name, size_t length,
                         napi_callback callback, void* data, napi_value* result) {
    if (g_origCreateFunction == nullptr) {
        return 1;
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

void InstallNapiHooksLocked() {
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


void* DeferredInstallThread(void*) {
    long delayUs = 150000;
    const char* delayEnv = ::getenv("NEXUSLAB_HOOK_DELAY_MS");
    if (delayEnv != nullptr && *delayEnv != 0) {
        delayUs = ::strtol(delayEnv, nullptr, 10) * 1000;
        if (delayUs < 0) {
            delayUs = 0;
        }
    }
    if (delayUs > 0) {
        ::usleep(static_cast<useconds_t>(delayUs));
    }
    InstallNapiHooksLocked();
    const char* dir = ::getenv("NEXUSLAB_RUNTIME_DIR");
    if (dir == nullptr || *dir == 0) {
        dir = "/run/user/0/nexuslab";
    }
    nexuslab_linux_hook_start_dynamic(dir);
    return nullptr;
}

void InstallNapiHooks() {
    pthread_t thread;
    const int rc = ::pthread_create(&thread, nullptr, DeferredInstallThread, nullptr);
    if (rc != 0) {
        InstallNapiHooksLocked();
        return;
    }
    ::pthread_detach(thread);
}


extern "C" int nexuslab_napi_bridge_available() {
    return g_sendTsfn.load() != nullptr ? 1 : 0;
}

extern "C" int nexuslab_napi_bridge_post(uint32_t requestId, const char* cmd, const void* body, uint32_t bodyLen) {
    napi_threadsafe_function tsfn = g_sendTsfn.load();
    if (tsfn == nullptr || cmd == nullptr) {
        return 0;
    }
    SendBridgeRequest* req = new(std::nothrow) SendBridgeRequest();
    if (req == nullptr) {
        return 0;
    }
    req->requestId = requestId;
    std::snprintf(req->cmd, sizeof(req->cmd), "%s", cmd);
    if (body != nullptr && bodyLen > 0) {
        req->body.assign(static_cast<const char*>(body), bodyLen);
    }
    if (g_api.callThreadsafe == nullptr) {
        LogLine("[bridge] callThreadsafe api missing");
        delete req;
        return 0;
    }
    const int callRc = g_api.callThreadsafe(tsfn, req, 0);
    LogLine("[bridge] callThreadsafe rc=%d", callRc);
    if (callRc != 0) {
        delete req;
        return 0;
    }
    return 1;
}

extern "C" void* nexuslab_napi_get_send_tsfn() {
    return reinterpret_cast<void*>(g_sendTsfn.load());
}

}  // namespace nexuslab_napi
