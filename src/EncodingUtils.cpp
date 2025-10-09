#include "EncodingUtils.hpp"
#include <zlib.h>
#include <stdexcept>
#include <bits/stdc++.h>

std::string gzip_decompress(const std::string& compressed_data) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        throw std::runtime_error("inflateInit2 failed for gzip");
    }

    zs.next_in = (Bytef*)compressed_data.data();
    zs.avail_in = compressed_data.size();

    int ret;
    std::vector<char> buffer(32768);
    std::string decompressed_string;

    do {
        zs.next_out = (Bytef*)buffer.data();
        zs.avail_out = buffer.size();
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret < 0 && ret != Z_BUF_ERROR) {
            inflateEnd(&zs);
            throw std::runtime_error("gzip decompression failed");
        }
        decompressed_string.append(buffer.data(), buffer.size() - zs.avail_out);
    } while (zs.avail_out == 0);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) {
        return "[Gzip Decompression Incomplete]";
    }

    return decompressed_string;
}