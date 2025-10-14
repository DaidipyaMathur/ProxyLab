#include "EncodingUtils.hpp"
#include <zlib.h>
#include <stdexcept>
#include <cstring>
#include <string>
#include <vector>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <algorithm>

// Base64 
static const char* B64_CHARS =
 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
 "abcdefghijklmnopqrstuvwxyz"
 "0123456789+/";

static inline bool is_b64_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/';
}

std::string base64_encode(const std::string& in) {
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(in.data());
    size_t in_len = in.size();
    std::string ret;
    ret.reserve(((in_len + 2) / 3) * 4);

    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    size_t pos = 0;
    while (in_len--) {
        char_array_3[i++] = bytes_to_encode[pos++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; i < 4; i++) ret += B64_CHARS[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        for (int j = 0; j < i + 1; j++) ret += B64_CHARS[char_array_4[j]];
        while (i++ < 3) ret += '=';
    }
    return ret;
}

std::string base64_decode(const std::string& encoded_string) {
    size_t in_len = encoded_string.size();
    int i = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;
    ret.reserve((in_len / 4) * 3);

    while (in_len-- && encoded_string[in_] != '=') {
        char c = encoded_string[in_];
        if (!is_b64_char(c)) { ++in_; continue; } // skip non-base64 chars
        char_array_4[i++] = c; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                const char* p = std::strchr(B64_CHARS, char_array_4[i]);
                if (!p) throw std::runtime_error("Invalid Base64 input");
                char_array_4[i] = static_cast<unsigned char>(p - B64_CHARS);
            }
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++) ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++) char_array_4[j] = 0;
        for (int j = 0; j < 4; j++) {
            const char* p = std::strchr(B64_CHARS, char_array_4[j]);
            char_array_4[j] = p ? static_cast<unsigned char>(p - B64_CHARS) : 0;
        }
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (int j = 0; j < i - 1; j++) ret += char_array_3[j];
    }
    return ret;
}

// URL encode/decode 
std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else if (c == ' ') {
            escaped << '+'; // common for form encoding
        } else {
            escaped << '%' << std::uppercase << std::setw(2) << int(c) << std::nouppercase;
        }
    }
    return escaped.str();
}

std::string url_decode(const std::string &value) {
    std::string result;
    result.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        char c = value[i];
        if (c == '+') {
            result += ' ';
        } else if (c == '%' && i + 2 < value.size() &&
                   std::isxdigit(static_cast<unsigned char>(value[i+1])) &&
                   std::isxdigit(static_cast<unsigned char>(value[i+2]))) {
            std::string hex = value.substr(i + 1, 2);
            char decoded = static_cast<char>(std::stoi(hex, nullptr, 16));
            result += decoded;
            i += 2;
        } else {
            result += c;
        }
    }
    return result;
}

//  Hex encode/decode 
std::string hex_encode(const std::string &in) {
    static const char* hex_chars = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (unsigned char c : in) {
        out.push_back(hex_chars[c >> 4]);
        out.push_back(hex_chars[c & 0x0F]);
    }
    return out;
}

std::string hex_decode(const std::string &in) {
    std::string out;
    out.reserve(in.size() / 2);
    auto hexval = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t len = in.size();
    if (len % 2 != 0) throw std::runtime_error("hex_decode: odd length");
    for (size_t i = 0; i < len; i += 2) {
        int hi = hexval(in[i]);
        int lo = hexval(in[i+1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("hex_decode: invalid hex digit");
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

//Gzip decompress
std::string gzip_decompress(const std::string& compressed_data) {
    if (compressed_data.empty()) return {};

    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));

    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        throw std::runtime_error("inflateInit2 failed for gzip");
    }

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed_data.data()));
    zs.avail_in = static_cast<uInt>(compressed_data.size());

    std::vector<char> buffer(32768);
    std::string decompressed;
    int ret = 0;

    do {
        zs.next_out = reinterpret_cast<Bytef*>(buffer.data());
        zs.avail_out = static_cast<uInt>(buffer.size());

        ret = inflate(&zs, 0);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            inflateEnd(&zs);
            throw std::runtime_error("gzip decompression failed");
        }
        std::size_t have = buffer.size() - zs.avail_out;
        if (have) decompressed.append(buffer.data(), have);
    } while (ret != Z_STREAM_END);

    inflateEnd(&zs);

    return decompressed;
}

// Gzip compress 
std::string gzip_compress(const std::string& raw_data, int level = Z_BEST_COMPRESSION) {
    if (raw_data.empty()) return {};

    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, level, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("deflateInit2 failed for gzip");
    }

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(raw_data.data()));
    zs.avail_in = static_cast<uInt>(raw_data.size());

    std::vector<char> buffer(32768);
    std::string compressed;
    int ret;

    do {
        zs.next_out = reinterpret_cast<Bytef*>(buffer.data());
        zs.avail_out = static_cast<uInt>(buffer.size());

        ret = deflate(&zs, zs.avail_in ? Z_NO_FLUSH : Z_FINISH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            deflateEnd(&zs);
            throw std::runtime_error("gzip compression failed");
        }
        std::size_t have = buffer.size() - zs.avail_out;
        if (have) compressed.append(buffer.data(), have);
    } while (ret != Z_STREAM_END);

    deflateEnd(&zs);
    return compressed;
}
