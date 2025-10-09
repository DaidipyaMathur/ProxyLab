#ifndef ENCODINGUTILS_HPP
#define ENCODINGUTILS_HPP

#include <string>

// Decompresses a gzip-encoded string
std::string gzip_decompress(const std::string& compressed_data);

#endif // ENCODINGUTILS_HPP
