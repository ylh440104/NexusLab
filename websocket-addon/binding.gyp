{
  "targets": [
    {
      "target_name": "websocket_addon",
      "sources": [ "addon.cc" ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTION" ],
      "conditions": [
        [ "OS==\"win\"", { "msvs_settings": { "VCCLCompilerTool": { "ExceptionHandling": 1 } } } ]
      ]
    }
  ]
}
