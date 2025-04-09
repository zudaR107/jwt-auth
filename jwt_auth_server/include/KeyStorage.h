#pragma once
#include "RSA.h"

class KeyStorage {
public:
    static bool loadKeys(RSAPublicKey& pubKey, RSAPrivateKey& privKey);
    static void saveKeys(const RSAPublicKey& pubKey, const RSAPrivateKey& privKey);
};
