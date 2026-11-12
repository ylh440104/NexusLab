{
  "targets": [
    {
      "target_name": "nexuslab",
      "sources": [
        "src/probe_win32.cc",
        "src/manual_map.cc"
      ],
      "libraries": ["rstrtmgr.lib"],
      "defines": ["NAPI_VERSION=8", "UNICODE", "_UNICODE"],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "ExceptionHandling": 1,
          "AdditionalOptions": ["/std:c++17"]
        }
      }
    }
  ]
}