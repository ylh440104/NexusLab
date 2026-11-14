#!/bin/sh
set -eu
SRC=linux-injector/injector.cc
OUT=linux-injector/test/inject_cli.cc
END=$(grep -n 'typedef Napi::Value' "$SRC" | head -1 | cut -d: -f1)
END=$((END - 1))
head -n "$END" "$SRC" | sed 's|#include <napi.h>||' > "$OUT"
cat >> "$OUT" <<'CEOF'
#include <cstdio>
#include <cstdlib>
#include <string>
int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: %s <pid> <so-path>\n", argv[0]);
        return 2;
    }
    pid_t pid = static_cast<pid_t>(std::atoi(argv[1]));
    std::string path = argv[2];
    std::printf("target pid=%d so=%s\n", static_cast<int>(pid), path.c_str());
    unsigned long base = 0;
    bool ok = InjectLibrary(pid, path, nullptr, &base);
    std::printf("inject ok=%d err=%s\n", ok ? 1 : 0, g_error.c_str());
    if (ok) std::printf("module base=0x%lx\n", base);
    return ok ? 0 : 1;
}
CEOF
echo "generated $OUT (core ends at $END)"
