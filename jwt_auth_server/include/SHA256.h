#pragma once
#include <string>

class SHA256 {
public:
    static std::string hash(const std::string& input);
};
