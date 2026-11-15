#include <node_api.h>
#include <stdio.h>
#include <string.h>

static int g_target_calls = 0;
static char g_last_payload[256];

static napi_value TargetSend(napi_env env, napi_callback_info info) {
    g_target_calls++;
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (argc > 0) {
        size_t len = 0;
        napi_get_value_string_utf8(env, argv[0], g_last_payload, sizeof(g_last_payload), &len);
    }
    napi_value result;
    napi_create_int32(env, g_target_calls, &result);
    return result;
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
    return obj;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor props[] = {
        { "SendSSORequestInternal", NULL, TargetSend, NULL, NULL, NULL, napi_default, NULL },
        { "RecvPacket", NULL, TargetRecv, NULL, NULL, NULL, napi_default, NULL },
        { "getStats", NULL, GetStats, NULL, NULL, NULL, napi_default, NULL },
    };
    napi_define_properties(env, exports, 3, props);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
