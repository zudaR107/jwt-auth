#pragma once
#include <string>

class PasswordEncryptor {
public:
    static std::string hashPassword(const std::string& password);
};
