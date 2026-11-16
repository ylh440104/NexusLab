#include <node_api.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_target_calls = 0;
static char g_last_payload[256];
static char g_last_cmd[128];
static int g_async_mode = 0;
static napi_ref g_exportsRef = NULL;

static napi_value TargetSend(napi_env env, napi_callback_info info) {
    g_target_calls++;
    size_t argc = 3;
    napi_value argv[3];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    char cmd[128] = {0};
    size_t bodyLen = 0;
    void* bodyData = NULL;
    if (argc > 0) {
        size_t n = 0;
        napi_get_value_string_utf8(env, argv[0], cmd, sizeof(cmd), &n);
    }
    if (argc > 1) {
        napi_get_buffer_info(env, argv[1], &bodyData, &bodyLen);
    }
    snprintf(g_last_cmd, sizeof(g_last_cmd), "%s", cmd);
    if (bodyData && bodyLen < sizeof(g_last_payload)) {
        memcpy(g_last_payload, bodyData, bodyLen);
        g_last_payload[bodyLen] = 0;
    }
    char ack[320];
    snprintf(ack, sizeof(ack), "ack:%s:%zu", cmd, bodyLen);
    napi_value result;
    napi_create_string_utf8(env, ack, NAPI_AUTO_LENGTH, &result);
    return result;
}

static napi_value TargetSendOneArg(napi_env env, napi_callback_info info) {
    g_target_calls++;
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    char cmd[128] = {0};
    if (argc > 0) {
        size_t n = 0;
        napi_get_value_string_utf8(env, argv[0], cmd, sizeof(cmd), &n);
    }
    snprintf(g_last_cmd, sizeof(g_last_cmd), "%s", cmd);
    g_last_payload[0] = 0;
    char ack[320];
    snprintf(ack, sizeof(ack), "one:%s", cmd);
    napi_value result;
    napi_create_string_utf8(env, ack, NAPI_AUTO_LENGTH, &result);
    return result;
}

static napi_value ResolveWith(napi_env env, napi_callback_info info) {
    napi_value result;
    napi_create_string_utf8(env, "resolved-value", NAPI_AUTO_LENGTH, &result);
    return result;
}

static napi_value TargetSendAsync(napi_env env, napi_callback_info info) {
    g_target_calls++;
    size_t argc = 2;
    napi_value argv[2];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    char cmd[128] = {0};
    size_t bodyLen = 0;
    void* bodyData = NULL;
    if (argc > 0) {
        size_t n = 0;
        napi_get_value_string_utf8(env, argv[0], cmd, sizeof(cmd), &n);
    }
    if (argc > 1) {
        napi_get_buffer_info(env, argv[1], &bodyData, &bodyLen);
    }
    snprintf(g_last_cmd, sizeof(g_last_cmd), "%s", cmd);
    if (bodyData && bodyLen < sizeof(g_last_payload)) {
        memcpy(g_last_payload, bodyData, bodyLen);
        g_last_payload[bodyLen] = 0;
    }
    napi_value promise, resolve, reject;
    napi_create_promise(env, &promise, &reject);
    napi_value fn;
    napi_create_function(env, "resolveWith", NAPI_AUTO_LENGTH, ResolveWith, NULL, &fn);
    char ack[320];
    snprintf(ack, sizeof(ack), "async:%s:%zu", cmd, bodyLen);
    napi_value arg;
    napi_create_string_utf8(env, ack, NAPI_AUTO_LENGTH, &arg);
    napi_value global;
    napi_get_global(env, &global);
    napi_value callResult;
    napi_call_function(env, global, fn, 1, &arg, &callResult);
    napi_value thenFn;
    napi_get_named_property(env, promise, "then", &thenFn);
    napi_value resolver;
    napi_create_function(env, "onThen", NAPI_AUTO_LENGTH, ResolveWith, NULL, &resolver);
    napi_value chain;
    napi_call_function(env, promise, thenFn, 1, &resolver, &chain);
    return promise;
}

static napi_value TargetRecv(napi_env env, napi_callback_info info) {
    napi_value result;
    napi_create_int32(env, 42, &result);
    return result;
}

static napi_value GetStats(napi_env env, napi_callback_info info) {
    napi_value obj, v;
    napi_create_object(env, &obj);
    napi_create_int32(env, g_target_calls, &v);
    napi_set_named_property(env, obj, "targetCalls", v);
    napi_create_string_utf8(env, g_last_payload, NAPI_AUTO_LENGTH, &v);
    napi_set_named_property(env, obj, "lastPayload", v);
    napi_create_string_utf8(env, g_last_cmd, NAPI_AUTO_LENGTH, &v);
    napi_set_named_property(env, obj, "lastCmd", v);
    return obj;
}

static napi_value SetVariant(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    int32_t mode = 0;
    if (argc > 0) {
        napi_get_value_int32(env, argv[0], &mode);
    }
    g_async_mode = mode;
    if (g_exportsRef != NULL) {
        napi_value exports = NULL;
        napi_get_reference_value(env, g_exportsRef, &exports);
        if (exports != NULL) {
            napi_value replacement = NULL;
            if (mode == 1) {
                napi_create_function(env, "SendSSORequestInternal", NAPI_AUTO_LENGTH, TargetSendOneArg, NULL, &replacement);
            } else if (mode == 2) {
                napi_create_function(env, "SendSSORequestInternal", NAPI_AUTO_LENGTH, TargetSendAsync, NULL, &replacement);
            } else {
                napi_create_function(env, "SendSSORequestInternal", NAPI_AUTO_LENGTH, TargetSend, NULL, &replacement);
            }
            if (replacement != NULL) {
                napi_set_named_property(env, exports, "SendSSORequestInternal", replacement);
            }
        }
    }
    napi_value result;
    napi_create_int32(env, mode, &result);
    return result;
}

static napi_value Init(napi_env env, napi_value exports) {
    const char* variant = getenv("MOCK_VARIANT");
    int mode = 0;
    if (variant != NULL && variant[0] != 0) {
        mode = atoi(variant);
    }
    napi_callback target = TargetSend;
    if (mode == 1) {
        target = TargetSendOneArg;
    } else if (mode == 2) {
        target = TargetSendAsync;
    }
    napi_property_descriptor props[] = {
        { "SendSSORequestInternal", NULL, target, NULL, NULL, NULL, napi_default, NULL },
        { "RecvPacket", NULL, TargetRecv, NULL, NULL, NULL, napi_default, NULL },
        { "getStats", NULL, GetStats, NULL, NULL, NULL, napi_default, NULL },
    };
    napi_define_properties(env, exports, 3, props);
    napi_create_reference(env, exports, 1, &g_exportsRef);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
