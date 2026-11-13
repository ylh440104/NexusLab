#include <napi.h>
#include <cstring>
#include <string>
#include <vector>

namespace {

class Parser {
    struct EmitFrame {
        bool fin;
        int rsv;
        int opcode;
        std::vector<uint8_t> payload;
    };

public:
    Parser(bool isServer, long long maxPayload, int allowedRsv)
        : isServer_(isServer),
          maxPayload_(maxPayload < 0 ? 0 : static_cast<uint64_t>(maxPayload)),
          allowedRsv_(allowedRsv & 0x70) {}

    Napi::Object Push(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        if (info.Length() < 1 || !info[0].IsBuffer()) {
            Napi::TypeError::New(env, "Parser.push expects a Buffer").ThrowAsJavaScriptException();
            return Napi::Object::New(env);
        }
        Napi::Buffer<uint8_t> chunk = info[0].As<Napi::Buffer<uint8_t>>();
        const uint8_t* data = chunk.Data();
        size_t size = chunk.Length();
        error_ = 0;
        message_.clear();
        emitFrames_.clear();

        size_t offset = 0;
        if (headGot_ > 0) {
            size_t pending = headGot_;
            size_t fill = size < (sizeof(headBuf_) - pending) ? size : (sizeof(headBuf_) - pending);
            std::memcpy(headBuf_ + pending, data, fill);
            size_t total = pending + fill;
            size_t consumed = 0;
            bool ok = step(headBuf_, total, &consumed);
            TakeFrameIfDone();
            if (!ok) {
                headGot_ = total;
                return Finish(env);
            }
            headGot_ = 0;
            size_t ahead = consumed > pending ? (consumed - pending) : 0;
            data += ahead;
            size -= ahead;
        }

        while (offset < size && error_ == 0) {
            size_t consumed = 0;
            State before = state_;
            bool ok = step(data + offset, size - offset, &consumed);
            TakeFrameIfDone();
            if (!ok) {
                if (state_ == State::Header && consumed == 0) {
                    size_t remain = size - offset;
                    if (remain > 0 && remain <= sizeof(headBuf_)) {
                        std::memcpy(headBuf_, data + offset, remain);
                        headGot_ = remain;
                    }
                }
                break;
            }
            offset += consumed;
            if (consumed == 0 && state_ == before) {
                break;
            }
        }
        return Finish(env);
    }

private:
    Napi::Object Finish(Napi::Env env) {
        Napi::Object result = Napi::Object::New(env);
        Napi::Array frames = Napi::Array::New(env);
        for (const auto& f : emitFrames_) {
            Napi::Object frame = Napi::Object::New(env);
            frame.Set("fin", Napi::Boolean::New(env, f.fin));
            frame.Set("rsv", Napi::Number::New(env, static_cast<double>(f.rsv)));
            frame.Set("opcode", Napi::Number::New(env, static_cast<double>(f.opcode)));
            frame.Set("payload", Napi::Buffer<uint8_t>::Copy(env, f.payload.data(), f.payload.size()));
            frames.Set(frames.Length(), frame);
        }
        result.Set("frames", frames);
        if (error_ != 0) {
            result.Set("error", Napi::Boolean::New(env, true));
            result.Set("code", Napi::Number::New(env, static_cast<double>(error_)));
            result.Set("message", Napi::String::New(env, message_.c_str()));
        }
        return result;
    }

    void TakeFrameIfDone() {
        if (!frameDone_) return;
        frameDone_ = false;
        EmitFrame out;
        out.fin = lastFin_;
        out.rsv = lastRsv_ << 4;
        out.opcode = lastOpcode_;
        out.payload.assign(frameBuf_.begin(), frameBuf_.begin() + static_cast<long>(frameLen_));
        emitFrames_.push_back(std::move(out));
    }


    void flushFrame() {
        if (!frameDone_) return;
        frameDone_ = false;
        EmitFrame f;
        f.fin = lastFin_; f.rsv = lastRsv_ << 4; f.opcode = lastOpcode_;
        f.payload.assign(frameBuf_.begin(), frameBuf_.begin() + (long)frameLen_);
        emitFrames_.push_back(f);
    }
    void fail(int code, const char* msg) { error_ = code; message_ = msg; }

    bool step(const uint8_t* d, size_t size, size_t* consumed) {
        if (state_ == State::Payload) {
            size_t need = frameLen_ - got_;
            size_t take = need < size ? need : size;
            if (masked_) {
                for (size_t i = 0; i < take; ++i) frameBuf_[got_ + i] = d[i] ^ mask_[(got_ + i) & 3];
            } else {
                memcpy(frameBuf_.data() + got_, d, take);
            }
            got_ += take; *consumed = take;
            if (got_ == frameLen_) { frameDone_ = true; state_ = State::Header; }
            return true;
        }
        if (state_ == State::Header) {
            if (size < 2) { *consumed = 0; return false; }
            uint8_t b0 = d[0], b1 = d[1];
            bool fin = (b0 & 0x80) != 0;
            int rsv = (b0 >> 4) & 7;
            int op = b0 & 0x0F;
            bool masked = (b1 & 0x80) != 0;
            uint64_t len7 = b1 & 0x7F;
            if ((op >= 3 && op <= 7) || (op >= 0xB && op <= 0xF)) { fail(1002, "Unknown opcode"); return false; }
            bool ctrl = op >= 8;
            if (ctrl) {
                if (rsv != 0) { fail(1002, "Control frame RSV bits must be zero"); return false; }
                if (!fin) { fail(1002, "Fragmented control frame"); return false; }
                if (len7 >= 126) { fail(1002, "Control frame too large"); return false; }
            } else {
                if (rsv != 0 && ((rsv << 4) & allowedRsv_) != (rsv << 4)) { fail(1002, "Unexpected RSV bits"); return false; }
            }
            if (isServer_ && !masked) { fail(1002, "Expected masked frame from client"); return false; }
            if (!isServer_ && masked) { fail(1002, "Server must not mask frames"); return false; }
            lastFin_ = fin; lastRsv_ = rsv; lastOpcode_ = op; masked_ = masked;
            uint64_t len = 0;
            size_t headerBytes = 2;
            if (len7 < 126) {
                len = len7;
            } else if (len7 == 126) {
                if (size < 4) { *consumed = 0; return false; }
                len = ((uint64_t)d[2] << 8) | d[3];
                headerBytes = 4;
                if (len < 126) { fail(1002, "Non-minimal 16-bit length"); return false; }
            } else {
                if (size < 10) { *consumed = 0; return false; }
                for (int i = 0; i < 8; ++i) len = (len << 8) | d[2 + i];
                headerBytes = 10;
                if (len & 0x8000000000000000ULL) { fail(1002, "Payload length top bit set"); return false; }
                if (len < 65536) { fail(1002, "Non-minimal 64-bit length"); return false; }
            }
            if (len > maxPayload_) { fail(1009, "Payload exceeds configured max"); return false; }
            frameLen_ = (size_t)len;
            if (masked) {
                if (size < headerBytes + 4) { *consumed = 0; return false; }
                memcpy(mask_, d + headerBytes, 4);
                headerBytes += 4;
            } else {
                memset(mask_, 0, 4);
            }
            *consumed = headerBytes;
            return enterPayload();
        }
        *consumed = 0; return false;
    }


    bool enterPayload() {
        if (frameLen_ > maxPayload_) { fail(1009, "Payload exceeds configured max"); return false; }
        if (frameLen_ == 0) { frameDone_ = true; state_ = State::Header; return true; }
        if (frameBuf_.size() < frameLen_) frameBuf_.resize(frameLen_);
        got_ = 0;
        state_ = State::Payload;
        return true;
    }
enum class State { Header, Payload };
    uint8_t headBuf_[10] = { 0 };
    size_t headGot_ = 0;
    bool isServer_;
    uint64_t maxPayload_;
    int allowedRsv_;
    State state_ = State::Header;
    bool masked_ = false;
    uint8_t mask_[4] = { 0, 0, 0, 0 };
    size_t frameLen_ = 0;
    size_t got_ = 0;
    bool frameDone_ = false;
    std::vector<EmitFrame> emitFrames_;
    bool lastFin_ = false;
    int lastRsv_ = 0;
    int lastOpcode_ = 0;
    int error_ = 0;
    std::string message_;
    std::vector<uint8_t> frameBuf_;
};

class ParserWrap : public Napi::ObjectWrap<ParserWrap> {
public:
    static Napi::Object Init(Napi::Env env, const Napi::Object& exports) {
        Napi::Function ctor = DefineClass(env, "Parser", {
            InstanceMethod("push", &ParserWrap::Push),
        });
        exports.Set("Parser", ctor);
        return exports;
    }
    ParserWrap(const Napi::CallbackInfo& info) : Napi::ObjectWrap<ParserWrap>(info) {
        Napi::Env env = info.Env();
        bool isServer = true;
        long long maxPayload = 0;
        int allowedRsv = 0;
        if (info.Length() >= 1 && info[0].IsObject()) {
            Napi::Object opts = info[0].As<Napi::Object>();
            if (opts.Has("isServer")) {
                isServer = opts.Get("isServer").ToBoolean().Value();
            }
            if (opts.Has("maxPayload")) {
                Napi::Number n = opts.Get("maxPayload").As<Napi::Number>();
                maxPayload = static_cast<long long>(n.Int64Value());
            }
            if (opts.Has("allowedRsv")) {
                allowedRsv = static_cast<int>(opts.Get("allowedRsv").As<Napi::Number>().Int32Value());
            }
        }
        parser_ = std::make_unique<Parser>(isServer, maxPayload, allowedRsv);
    }

private:
    Napi::Value Push(const Napi::CallbackInfo& info) {
        return parser_->Push(info);
    }
    std::unique_ptr<Parser> parser_;
};

Napi::Value BuildFrame(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsNumber() || !info[1].IsBoolean() || !info[2].IsBuffer()) {
        Napi::TypeError::New(env, "buildFrame: bad args").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    int opcode = info[0].As<Napi::Number>().Int32Value();
    bool fin = info[1].As<Napi::Boolean>().Value();
    Napi::Buffer<uint8_t> payload = info[2].As<Napi::Buffer<uint8_t>>();
    bool hasMask = info.Length() >= 4 && info[3].IsBuffer();
    uint8_t mask[4] = { 0, 0, 0, 0 };
    if (hasMask) {
        Napi::Buffer<uint8_t> mk = info[3].As<Napi::Buffer<uint8_t>>();
        if (mk.Length() != 4) {
            Napi::TypeError::New(env, "mask key must be 4 bytes").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        std::memcpy(mask, mk.Data(), 4);
    }
    int rsv = 0;
    if (info.Length() >= 5 && info[4].IsNumber()) {
        rsv = static_cast<int>(info[4].As<Napi::Number>().Int32Value());
    }

    size_t len = payload.Length();
    size_t headerLen = 2;
    if (len >= 126 && len <= 0xFFFF) {
        headerLen = 4;
    } else if (len > 0xFFFF) {
        headerLen = 10;
    }
    if (hasMask) {
        headerLen += 4;
    }
    size_t total = headerLen + len;
    Napi::Buffer<uint8_t> out = Napi::Buffer<uint8_t>::New(env, total);
    uint8_t* outData = out.Data();
    const uint8_t* in = payload.Data();

    uint8_t b0 = static_cast<uint8_t>((fin ? 0x80 : 0x00) | (rsv & 0x70) | (opcode & 0x0F));
    uint8_t b1 = hasMask ? 0x80 : 0x00;
    outData[0] = b0;
    if (len < 126) {
        outData[1] = static_cast<uint8_t>(b1 | len);
    } else if (len <= 0xFFFF) {
        outData[1] = static_cast<uint8_t>(b1 | 126);
        outData[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
        outData[3] = static_cast<uint8_t>(len & 0xFF);
    } else {
        outData[1] = static_cast<uint8_t>(b1 | 127);
        uint64_t v = static_cast<uint64_t>(len);
        for (int i = 0; i < 8; ++i) {
            outData[2 + i] = static_cast<uint8_t>((v >> (56 - i * 8)) & 0xFF);
        }
    }
    size_t payloadStart = headerLen;
    if (hasMask) {
        std::memcpy(outData + headerLen - 4, mask, 4);
        for (size_t i = 0; i < len; ++i) {
            outData[payloadStart + i] = in[i] ^ mask[i & 3];
        }
    } else {
        std::memcpy(outData + payloadStart, in, len);
    }
    return out;
}

Napi::Value ComputeAcceptKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "computeAcceptKey: expected string").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string key = info[0].As<Napi::String>().Utf8Value();
    static const char magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string input = key + magic;

    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint64_t bitLen = static_cast<uint64_t>(input.size()) * 8;
    std::string padded = input;
    padded.push_back(static_cast<char>(0x80));
    while (padded.size() % 64 != 56) {
        padded.push_back('\0');
    }
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<char>((bitLen >> (i * 8)) & 0xFF));
    }

    uint32_t w[80];
    for (size_t block = 0; block < padded.size(); block += 64) {
        for (int t = 0; t < 16; ++t) {
            w[t] = (static_cast<unsigned char>(padded[block + t * 4]) << 24) |
                   (static_cast<unsigned char>(padded[block + t * 4 + 1]) << 16) |
                   (static_cast<unsigned char>(padded[block + t * 4 + 2]) << 8) |
                   static_cast<unsigned char>(padded[block + t * 4 + 3]);
        }
        for (int t = 16; t < 80; ++t) {
            uint32_t val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (val << 1) | (val >> 31);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int t = 0; t < 80; ++t) {
            uint32_t f, k;
            if (t < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t digest[20];
    for (int i = 0; i < 5; ++i) {
        digest[i * 4] = static_cast<uint8_t>(h[i] >> 24);
        digest[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
        digest[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
        digest[i * 4 + 3] = static_cast<uint8_t>(h[i]);
    }
    std::string b64;
    b64.reserve(28);
    for (int i = 0; i < 20; i += 3) {
        uint32_t triple = static_cast<uint32_t>(digest[i]) << 16;
        if (i + 1 < 20) triple |= static_cast<uint32_t>(digest[i + 1]) << 8;
        if (i + 2 < 20) triple |= digest[i + 2];
        b64.push_back(alphabet[(triple >> 18) & 0x3F]);
        b64.push_back(alphabet[(triple >> 12) & 0x3F]);
        b64.push_back((i + 1 < 20) ? alphabet[(triple >> 6) & 0x3F] : '=');
        b64.push_back((i + 2 < 20) ? alphabet[triple & 0x3F] : '=');
    }
    return Napi::String::New(env, b64);
}

Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
    ParserWrap::Init(env, exports);
    exports.Set("buildFrame", Napi::Function::New(env, BuildFrame));
    exports.Set("computeAcceptKey", Napi::Function::New(env, ComputeAcceptKey));
    return exports;
}

}

NODE_API_MODULE(nexuslab_websocket_addon, InitModule)
