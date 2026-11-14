{
  "targets": [
    {
      "target_name": "linux_injector",
      "sources": [
        "injector.cc",
        "core_proc.cc",
        "core_inject.cc",
        "core_elf.cc"
      ],
      "include_dirs": [ "node_modules/node-addon-api" ],
      "defines": [ "NAPI_CPP_EXCEPTIONS", "NODE_ADDON_API_CPP_EXCEPTIONS" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "cflags_cc": [ "-std=c++17" ],
      "conditions": [
        [ "OS=='win'", { "msvs_settings": { "VCCLCompilerTool": { "ExceptionHandling": 1 } } } ]
      ]
    }
  ]
}
