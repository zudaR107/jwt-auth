#pragma once
#include "RSA.h"
#include <string>
#include <cstdint>

class JWT {
public:
    static std::string createToken(const std::string& subject, 
                                   uint64_t expirationSeconds, 
                                   const RSAPrivateKey& privKey);
    static bool verifyToken(const std::string& token, 
                            const RSAPublicKey& pubKey, 
                            std::string& outSubject);

};
