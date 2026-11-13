{
  "targets": [
    {
      "target_name": "websocket_addon",
      "sources": [ "addon.cc" ],
      "include_dirs": [ "node_modules/node-addon-api" ],
      "defines": [ "NAPI_CPP_EXCEPTIONS", "NODE_ADDON_API_CPP_EXCEPTIONS" ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "conditions": [
        [ "OS=='win'", { "msvs_settings": { "VCCLCompilerTool": { "ExceptionHandling": 1 } } } ]
      ]
    }
  ]
}
