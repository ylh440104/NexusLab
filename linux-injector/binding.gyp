{
  "targets": [
    {
      "target_name": "linux_injector",
      "sources": [ "injector.cc" ],
      "include_dirs": [ "<!(node -p \"require('node-addon-api').include\")" ]
    }
  ]
}
