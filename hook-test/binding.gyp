{
  "targets": [
    {
      "target_name": "mock_addon",
      "sources": ["mock_addon.c"],
      "include_dirs": ["<!(node -p \"require('path').dirname(require.resolve('node-api-headers/package.json'))\")/include"]
    }
  ]
}
