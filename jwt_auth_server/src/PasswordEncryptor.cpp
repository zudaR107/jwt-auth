#include "../include/PasswordEncryptor.h"
#include "../include/SHA256.h"

std::string PasswordEncryptor::hashPassword(const std::string& password) {
    return SHA256::hash(password);
}

