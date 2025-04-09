#pragma once
#include <string>

class Base64URL {
public:
    static std::string encode(const std::string& input);
    static std::string decode(const std::string& input);
};
