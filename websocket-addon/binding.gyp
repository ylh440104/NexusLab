{
  "targets": [
    {
      "target_name": "websocket_addon",
      "sources": [ "addon.cc" ],
      "include_dirs": [ "<!(node -p \"require('node-addon-api').include\")" ]
    }
  ]
}
