#include "../include/RSA.h"
#include <random>
#include <chrono>
#include <iostream>

static bool is_prime(const BigInt& n, int iterations = 10) {
    if (n <= BigInt(1)) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if (n % BigInt(2) == BigInt(0)) return false;

    BigInt d = n - BigInt(1);
    int r = 0;

    while (d % BigInt(2) == BigInt(0)) {
        d = d / BigInt(2);
        r++;
    }

    std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());

    for (int i = 0; i < iterations; ++i) {
        BigInt a = BigInt(2 + rng() % 10000);
        BigInt x = BigInt::modPow(a, d, n);
        if (x == BigInt(1) || x == n - BigInt(1)) continue;

        bool continue_outer = false;
        for (int j = 0; j < r - 1; ++j) {
            x = BigInt::modPow(x, BigInt(2), n);
            if (x == n - BigInt(1)) {
                continue_outer = true;
                break;
            }
        }

        if (continue_outer) continue;
        return false;
    }

    return true;
}

static BigInt random_bigint(int bit_length) {
    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    BigInt result(0);
    for (int i = 0; i < bit_length; i += 4) {
        result = result * BigInt(10);
        result = result + BigInt(rng() % 10);
    }
    return result;
}

static BigInt modinv(const BigInt& a, const BigInt& m) {
    BigInt m0 = m, t, q;
    BigInt x0 = 0, x1 = 1;
    BigInt a_ = a;
    BigInt m_ = m;

    while (a_ > 1) {
        q = a_ / m_;
        t = m_;
        m_ = a_ % m_, a_ = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 = x1 + m0;

    return x1;
}

void RSA::generate_keys(RSAPublicKey& pub, RSAPrivateKey& priv, int bit_length) {
    std::cout << "[RSA] --- Генерация ключей ---" << std::endl;

    BigInt p, q;

    std::cout << "[RSA] Генерация простого p..." << std::endl;
    do {
        p = random_bigint(bit_length);
    } while (!is_prime(p));
    std::cout << "[RSA] Простое p: " << p.toString() << std::endl;

    std::cout << "[RSA] Генерация простого q..." << std::endl;
    do {
        q = random_bigint(bit_length);
    } while (!is_prime(q) || p == q);
    std::cout << "[RSA] Простое q: " << q.toString() << std::endl;

    BigInt n = p * q;
    BigInt phi = (p - BigInt(1)) * (q - BigInt(1));
    BigInt e = 65537;

    std::cout << "[RSA] n = p * q = " << n.toString() << std::endl;
    std::cout << "[RSA] phi = (p-1)*(q-1) = " << phi.toString() << std::endl;

    while (BigInt::gcd(e, phi) != BigInt(1)) {
        e = e + BigInt(2);
    }

    std::cout << "[RSA] Публичная экспонента e: " << e.toString() << std::endl;

    BigInt d = modinv(e, phi);
    std::cout << "[RSA] Приватная экспонента d: " << d.toString() << std::endl;

    pub = {e, n};
    priv = {d, n};

    std::cout << "[RSA] --- Ключи успешно сгенерированы ---" << std::endl;
}

BigInt RSA::encrypt(const BigInt& message, const RSAPublicKey& key) {
    std::cout << "[RSA] --- Шифрование ---" << std::endl;
    std::cout << "Message: " << message.toString(16) << std::endl;
    BigInt cipher = BigInt::modPow(message, key.e, key.n);
    std::cout << "Encrypted: " << cipher.toString(16) << std::endl;
    return cipher;
}

BigInt RSA::decrypt(const BigInt& cipher, const RSAPrivateKey& key) {
    std::cout << "[RSA] --- Расшифровка ---" << std::endl;
    std::cout << "Cipher: " << cipher.toString(16) << std::endl;
    BigInt message = BigInt::modPow(cipher, key.d, key.n);
    std::cout << "Decrypted: " << message.toString(16) << std::endl;
    return message;
}

BigInt RSA::sign(const BigInt& hash, const RSAPrivateKey& key) {
    std::cout << "[RSA] --- Подпись ---" << std::endl;
    std::cout << "Hash (hex): " << hash.toString(16) << std::endl;
    BigInt sig = BigInt::modPow(hash, key.d, key.n);
    std::cout << "Signature (hex): " << sig.toString(16) << std::endl;
    return sig;
}

bool RSA::verify(const std::string& messageHashHex, const BigInt& signature, const RSAPublicKey& key) {
    std::cout << "[RSA] --- Верификация подписи ---" << std::endl;
    std::cout << "Expected hash:  " << messageHashHex << std::endl;
    std::cout << "Signature:      " << signature.toString(16) << std::endl;

    BigInt decryptedHashInt = BigInt::modPow(signature, key.e, key.n);
    std::string decryptedHashHex = decryptedHashInt.toString(16);

    while (decryptedHashHex.length() < 64)
        decryptedHashHex = "0" + decryptedHashHex;

    std::cout << "Decrypted hash: " << decryptedHashHex << std::endl;

    bool valid = (decryptedHashHex == messageHashHex);
    std::cout << "Signature valid: " << (valid ? "YES" : "NO") << std::endl;

    return valid;
}
