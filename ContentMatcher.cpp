#include "ContentMatcher.h"
#include <CommonCrypto/CommonDigest.h>
#include <array>
#include <stdexcept>
#include <limits>
#include <zlib.h>

namespace agentsec {
std::string Sha256(const std::string& bytes) {
    if (bytes.size() > std::numeric_limits<CC_LONG>::max()) throw std::length_error("hash input too large");
    std::array<unsigned char, CC_SHA256_DIGEST_LENGTH> hash{};
    CC_SHA256(bytes.data(), static_cast<CC_LONG>(bytes.size()), hash.data());
    const char* hex = "0123456789abcdef";
    std::string result;
    for (auto byte : hash) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
std::string Base64(const std::string& bytes) {
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const auto a = static_cast<unsigned char>(bytes[i]);
        const auto b = i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0;
        const auto c = i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0;
        result += alphabet[a >> 2]; result += alphabet[((a & 3) << 4) | (b >> 4)];
        result += i + 1 < bytes.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
        result += i + 2 < bytes.size() ? alphabet[c & 63] : '=';
    }
    return result;
}
namespace {
std::string MatchPlainContent(const std::string& payload, const std::string& sensitive) {
    if (sensitive.size() < 16) return {}; // short common values are poor evidence
    if (payload.find(sensitive) != std::string::npos) return "exact_bytes";
    std::string escaped;
    const char* hex = "0123456789abcdef";
    for (unsigned char c : sensitive) {
        switch (c) {
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        default:
            if (c < 32) { escaped += "\\u00"; escaped += hex[c >> 4]; escaped += hex[c & 15]; }
            else escaped += static_cast<char>(c);
        }
    }
    if (payload.find(escaped) != std::string::npos) return "json_escaped_bytes";
    if (payload.find(Base64(sensitive)) != std::string::npos) return "base64_whole_value";
    return {};
}
}
std::string MatchContent(const std::string& payload, const std::string& sensitive) {
    auto match = MatchPlainContent(payload, sensitive);
    if (!match.empty()) return match;
    // One gzip member, at most 1 MiB expanded. Do not recursively decompress.
    if (payload.size() < 2 || static_cast<unsigned char>(payload[0]) != 0x1f ||
        static_cast<unsigned char>(payload[1]) != 0x8b || payload.size() > 1024 * 1024) return {};
    struct Inflater {
        z_stream stream{};
        bool initialized = false;
        ~Inflater() { if (initialized) inflateEnd(&stream); }
    } inflater;
    if (inflateInit2(&inflater.stream, 16 + MAX_WBITS) != Z_OK) return {};
    inflater.initialized = true;
    auto& stream = inflater.stream;
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(payload.data()));
    stream.avail_in = static_cast<uInt>(payload.size());
    std::string expanded;
    std::array<char, 8192> block{};
    int code;
    do {
        stream.next_out = reinterpret_cast<Bytef*>(block.data()); stream.avail_out = block.size();
        code = inflate(&stream, Z_NO_FLUSH);
        if (code != Z_OK && code != Z_STREAM_END) return {};
        const size_t count = block.size() - stream.avail_out;
        if (expanded.size() + count > 1024 * 1024) return {};
        expanded.append(block.data(), count);
    } while (code != Z_STREAM_END);
    if (stream.avail_in) return {}; // concatenated members/trailing bytes aren't covered
    match = MatchPlainContent(expanded, sensitive);
    return match.empty() ? std::string{} : "gzip:" + match;
}
uint64_t ContentLowerBound(const std::string& bytes) {
    if (bytes.empty() || bytes.size() > 1024 * 1024) return bytes.size();
    uint64_t best = bytes.size();
    for (const int window : {15 + 16, 15, -15}) {
        z_stream stream{};
        if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, window, 8, Z_DEFAULT_STRATEGY) != Z_OK) continue;
        struct Finish {
            z_stream* stream;
            ~Finish() { deflateEnd(stream); }
        } finish{&stream};
        const auto bound = deflateBound(&stream, static_cast<uLong>(bytes.size()));
        std::string out(static_cast<size_t>(bound) + 16, '\0');
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(bytes.data()));
        stream.avail_in = static_cast<uInt>(bytes.size());
        stream.next_out = reinterpret_cast<Bytef*>(out.data());
        stream.avail_out = static_cast<uInt>(out.size());
        if (deflate(&stream, Z_FINISH) == Z_STREAM_END && stream.total_out > 0 && stream.total_out < best)
            best = stream.total_out;
        for (char& byte : out) {
            volatile char* cell = &byte;
            *cell = 0;
        }
    }
    return best;
}
}
