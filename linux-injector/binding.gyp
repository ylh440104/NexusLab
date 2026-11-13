{
  "targets": [
    {
      "target_name": "linux_injector",
      "sources": [ "injector.cc" ],
      "include_dirs": [ "node_modules/node-addon-api" ],
      "defines": [ "NAPI_CPP_EXCEPTIONS", "NODE_ADDON_API_CPP_EXCEPTIONS" ]
    }
  ]
}
