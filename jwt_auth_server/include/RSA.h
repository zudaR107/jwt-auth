#pragma once
#include "BigInt.h"

struct RSAPublicKey {
    BigInt e;
    BigInt n;
};

struct RSAPrivateKey {
    BigInt d;
    BigInt n;
};

class RSA {
public:
    static void generate_keys(RSAPublicKey& pub, RSAPrivateKey& priv, int bit_length = 64);

    static BigInt encrypt(const BigInt& message, const RSAPublicKey& key);
    static BigInt decrypt(const BigInt& cipher, const RSAPrivateKey& key);

    static BigInt sign(const BigInt& hash, const RSAPrivateKey& key);
    static bool verify(const std::string& messageHashHex, 
                       const BigInt& signature, 
                       const RSAPublicKey& key);

};
