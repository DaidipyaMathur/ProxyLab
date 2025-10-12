// src/DataTypes.hpp

#ifndef DATATYPES_HPP
#define DATATYPES_HPP

#include <string>
#include <map>

// A struct to hold the parsed components of an HTTP message
struct ParsedHttpData {
    std::string start_line;
    std::map<std::string, std::string> headers;
    std::string body;
};

#endif // DATATYPES_HPP