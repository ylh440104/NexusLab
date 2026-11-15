#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <unistd.h>
#include <dirent.h>
#include <ctime>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include "napi_hook.h"

namespace {

constexpr uint32_t kPipeMagic = 0x31504851u;
constexpr uint16_t kPipeVersion = 1;
constexpr size_t kHeaderSize = 40;
constexpr size_t kMaxCmd = 4096;
constexpr size_t kMaxBody = 65536;
constexpr const char* kBackendVersion = "nexuslab-linux-hook/2.0.0";

struct PipeHeader {
    uint8_t magic[4];
    uint16_t version;
    uint16_t op;
    int32_t status;
    uint32_t flags;
    uint32_t requestId;
    uint64_t value0;
    uint32_t cmdLength;
    uint32_t bodyLength;
    uint32_t msgLength;
    uint32_t reserved;
};

char g_controlPath[108] = {0};
char g_recvPath[108] = {0};
std::atomic<bool> g_loaded{false};
std::atomic<bool> g_stopping{false};
std::thread g_controlThread;
std::thread g_recvThread;

bool WriteAll(int fd, const void* buf, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = ::write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        done += static_cast<size_t>(n);
    }
    return true;
}

bool ReadAll(int fd, void* buf, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = ::read(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

void BuildHeader(uint8_t* out, uint16_t op, int32_t status, uint32_t flags,
                 uint32_t requestId, uint64_t value0,
                 uint32_t cmdLen, uint32_t bodyLen, uint32_t msgLen) {
    std::memset(out, 0, kHeaderSize);
    out[0] = 0x51; out[1] = 0x48; out[2] = 0x50; out[3] = 0x31;
    std::memcpy(out + 4, &kPipeVersion, 2);
    std::memcpy(out + 6, &op, 2);
    std::memcpy(out + 8, &requestId, 4);
    std::memcpy(out + 12, &status, 4);
    std::memcpy(out + 16, &flags, 4);
    std::memcpy(out + 20, &cmdLen, 4);
    std::memcpy(out + 24, &msgLen, 4);
    std::memcpy(out + 28, &bodyLen, 4);
    std::memcpy(out + 32, &value0, 8);
}

int MakeListener(const char* path) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    ::unlink(path);
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        if (getenv("NEXUSLAB_HOOK_DEBUG") != nullptr) {
            std::fprintf(stderr, "[hook] bind failed path=%s errno=%d\n", path, errno);
        }
        ::close(fd);
        return -1;
    }
    ::chmod(path, 0600);
    if (::listen(fd, 4) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool SendHello(int fd, const char* name, uint32_t pid) {
    uint8_t buf[kHeaderSize + 64];
    BuildHeader(buf, 1, 0, 0, 0, pid, 0, static_cast<uint32_t>(std::strlen(name)), 0);
    std::memcpy(buf + kHeaderSize, name, std::strlen(name));
    return WriteAll(fd, buf, kHeaderSize + std::strlen(name));
}

struct LoginSnapshot {
    bool loggedIn;
    unsigned long long uin;
    char text[24];
};

LoginSnapshot DetectLoginState() {
    LoginSnapshot snap;
    snap.loggedIn = false;
    snap.uin = 0;
    snap.text[0] = 0;

    const char* home = ::getenv("HOME");
    std::string root = std::string(home && *home ? home : "/root") + "/.config/QQ/Partitions";
    DIR* dir = ::opendir(root.c_str());
    if (dir == nullptr) {
        return snap;
    }

    unsigned long long bestUin = 0;
    long long bestMtime = -1;
    struct dirent* entry = nullptr;
    while ((entry = ::readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        if (std::strncmp(name, "qqnt_", 5) != 0) {
            continue;
        }
        const char* digits = name + 5;
        size_t length = std::strlen(digits);
        if (length < 5 || length > 12) {
            continue;
        }
        bool numeric = true;
        for (size_t i = 0; i < length; ++i) {
            if (digits[i] < '0' || digits[i] > '9') {
                numeric = false;
                break;
            }
        }
        if (!numeric) {
            continue;
        }
        std::string full = root + "/" + name;
        struct stat info;
        if (::stat(full.c_str(), &info) != 0) {
            continue;
        }
        if (static_cast<long long>(info.st_mtime) > bestMtime) {
            bestMtime = static_cast<long long>(info.st_mtime);
            bestUin = std::strtoull(digits, nullptr, 10);
        }
    }
    ::closedir(dir);

    if (bestUin != 0) {
        snap.loggedIn = true;
        snap.uin = bestUin;
        std::snprintf(snap.text, sizeof(snap.text), "%llu", bestUin);
    }
    return snap;
}

void ReplyLoginState(int fd, uint32_t requestId) {
    LoginSnapshot snap = DetectLoginState();
    size_t textLength = snap.loggedIn ? std::strlen(snap.text) : 0;
    uint8_t out[kHeaderSize + 32];
    BuildHeader(out,
                7,
                snap.loggedIn ? 1 : 0,
                snap.loggedIn ? 4u : 0u,
                requestId,
                snap.loggedIn ? snap.uin : 0,
                0,
                0,
                static_cast<uint32_t>(textLength));
    if (textLength > 0) {
        std::memcpy(out + kHeaderSize, snap.text, textLength);
    }
    WriteAll(fd, out, kHeaderSize + textLength);
}

unsigned long long MonotonicMs() {
    struct timespec ts;
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return static_cast<unsigned long long>(ts.tv_sec) * 1000ull +
           static_cast<unsigned long long>(ts.tv_nsec) / 1000000ull;
}

void ControlSession(int fd) {
    SendHello(fd, g_controlPath, static_cast<uint32_t>(::getpid()));
    unsigned long long lastPush = 0;
    while (!g_stopping.load()) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int r = ::poll(&pfd, 1, 200);
        if (r < 0 && errno == EINTR) continue;
        const unsigned long long now = MonotonicMs();
        if (now - lastPush >= 1500ull || lastPush == 0) {
            ReplyLoginState(fd, 0);
            lastPush = now;
        }
        if (r <= 0) continue;
        uint8_t head[kHeaderSize];
        if (!ReadAll(fd, head, kHeaderSize)) break;
        if (std::memcmp(head, "QHP1", 4) != 0) break;
        uint16_t op;
        uint32_t requestId;
        std::memcpy(&op, head + 6, 2);
        std::memcpy(&requestId, head + 8, 4);
        uint32_t cmdLen, bodyLen, msgLen;
        std::memcpy(&cmdLen, head + 20, 4);
        std::memcpy(&msgLen, head + 24, 4);
        std::memcpy(&bodyLen, head + 28, 4);
        if (cmdLen > kMaxCmd || bodyLen > kMaxBody) {
            break;
        }
        std::vector<uint8_t> rest(static_cast<size_t>(cmdLen) + bodyLen + msgLen);
        if (!rest.empty() && !ReadAll(fd, rest.data(), rest.size())) break;

        if (op == 1) {
            if (!SendHello(fd, g_controlPath, static_cast<uint32_t>(::getpid()))) break;
            continue;
        }
        if (op == 7) {
            ReplyLoginState(fd, requestId);
            continue;
        }
        uint8_t out[kHeaderSize + 64];
        BuildHeader(out, 5, -2, 0, requestId, 0, 0, 0, static_cast<uint32_t>(std::strlen("unsupported pipe op")));
        std::memcpy(out + kHeaderSize, "unsupported pipe op", std::strlen("unsupported pipe op"));
        if (!WriteAll(fd, out, kHeaderSize + std::strlen("unsupported pipe op"))) break;
    }
    ::close(fd);
}

void ControlLoop() {
    int listener = MakeListener(g_controlPath);
    if (listener < 0) return;
    while (!g_stopping.load()) {
        struct pollfd pfd = { listener, POLLIN, 0 };
        int r = ::poll(&pfd, 1, 500);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) continue;
        int fd = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) continue;
        std::thread(ControlSession, fd).detach();
    }
    ::close(listener);
    ::unlink(g_controlPath);
}

void RecvSession(int fd) {
    SendHello(fd, g_recvPath, static_cast<uint32_t>(::getpid()));
    while (!g_stopping.load()) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int r = ::poll(&pfd, 1, 500);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) continue;
        uint8_t head[kHeaderSize];
        if (!ReadAll(fd, head, kHeaderSize)) break;
    }
    ::close(fd);
}

void RecvLoop() {
    int listener = MakeListener(g_recvPath);
    if (listener < 0) return;
    while (!g_stopping.load()) {
        struct pollfd pfd = { listener, POLLIN, 0 };
        int r = ::poll(&pfd, 1, 500);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) continue;
        int fd = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) continue;
        std::thread(RecvSession, fd).detach();
    }
    ::close(listener);
    ::unlink(g_recvPath);
}

std::string RuntimeDir() {
    const char* env = ::getenv("NEXUSLAB_RUNTIME_DIR");
    if (env && *env) return env;
    const char* xdg = ::getenv("XDG_RUNTIME_DIR");
    std::string base;
    if (xdg && *xdg) {
        base = xdg;
    } else {
        base = "/tmp";
    }
    std::string dir = base + "/nexuslab";
    ::mkdir(dir.c_str(), 0700);
    return dir;
}

}

extern "C" {

const char* nexuslab_linux_hook_backend_version() {
    return kBackendVersion;
}

int nexuslab_linux_hook_is_loaded() {
    return g_loaded.load() ? 1 : 0;
}

int nexuslab_linux_hook_start_dynamic(const char* runtimeDir) {
    if (g_loaded.load()) return 0;
    std::string dir = (runtimeDir && *runtimeDir) ? std::string(runtimeDir) : RuntimeDir();
    std::string cp = dir + "/mojo." + std::to_string(::getpid()) + ".control.sock";
    std::string rp = dir + "/mojo." + std::to_string(::getpid()) + ".recv.sock";
    ::mkdir(dir.c_str(), 0700);
    std::snprintf(g_controlPath, sizeof(g_controlPath), "%s", cp.c_str());
    std::snprintf(g_recvPath, sizeof(g_recvPath), "%s", rp.c_str());
    g_stopping.store(false);
    g_controlThread = std::thread(ControlLoop);
    g_recvThread = std::thread(RecvLoop);
    g_loaded.store(true);
    return 1;
}

int nexuslab_linux_hook_stop_dynamic() {
    if (!g_loaded.load()) return 0;
    g_stopping.store(true);
    if (g_controlThread.joinable()) g_controlThread.join();
    if (g_recvThread.joinable()) g_recvThread.join();
    ::unlink(g_controlPath);
    ::unlink(g_recvPath);
    g_loaded.store(false);
    return 1;
}

const char* nexuslab_linux_hook_control_socket() {
    return g_controlPath;
}

const char* nexuslab_linux_hook_recv_socket() {
    return g_recvPath;
}

}

bool IsElectronChildProcess() {
    int fd = ::open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    char buffer[4096];
    const ssize_t length = ::read(fd, buffer, sizeof(buffer) - 1);
    ::close(fd);
    if (length <= 0) {
        return false;
    }
    buffer[length] = 0;
    for (ssize_t i = 0; i < length; ++i) {
        if (buffer[i] == 0) {
            buffer[i] = ' ';
        }
    }
    return std::strstr(buffer, "--type=") != nullptr;
}

__attribute__((constructor, used, visibility("default"))) void nexuslab_auto_start() {
    if (g_loaded.load()) {
        return;
    }
    if (IsElectronChildProcess()) {
        return;
    }
    nexuslab_napi::InstallNapiHooks();
    const char* dir = ::getenv("NEXUSLAB_RUNTIME_DIR");
    nexuslab_linux_hook_start_dynamic(dir);
}
