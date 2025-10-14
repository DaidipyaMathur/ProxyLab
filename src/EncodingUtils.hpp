#ifndef ENCODINGUTILS_HPP
#define ENCODINGUTILS_HPP

#include <string>

std::string base64_encode(const std::string&);
std::string base64_decode(const std::string&);

std::string url_encode(const std::string&);
std::string url_decode(const std::string&);

std::string hex_encode(const std::string&);
std::string hex_decode(const std::string&);

std::string gzip_decompress(const std::string&);
std::string gzip_compress(const std::string&, int level = Z_BEST_COMPRESSION);


#endif // ENCODINGUTILS_HPP
