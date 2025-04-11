#pragma once
#include <string>
#include <cstdint>
#include "RSA.h"

class JWT {
public:
    static std::string createAccessToken(const std::string& subject, 
                                         uint64_t expirationSeconds, 
                                         const RSAPrivateKey& privKey);
    static bool verifyAccessToken(const std::string& token, 
                                  const RSAPublicKey& pubKey, 
                                  std::string& outSubject);

    static std::string createRefreshToken(const std::string& subject, 
                                          uint64_t expirationSeconds, 
                                          const RSAPrivateKey& privKey);
    static bool verifyRefreshToken(const std::string& token, 
                                   const RSAPublicKey& pubKey, 
                                   std::string& outSubject);
};
