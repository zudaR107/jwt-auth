#include "RSA.h"
#include <random>
#include <chrono>
#include <iostream>

static bool is_prime(const BigInt& n, int iterations = 10) {
    if (n <= BigInt(1)) return false;
    if (n == BigInt(2) || n == BigInt(3)) return true;
    if (n % BigInt(2) == BigInt(0)) return false;

    BigInt d = n - BigInt(1);
    int r = 0;

    // представим n - 1 = 2^r * d
    while (d % BigInt(2) == BigInt(0)) {
        d = d / BigInt(2);
        r++;
    }

    std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());

    for (int i = 0; i < iterations; ++i) {
        BigInt a = BigInt(2 + rng() % 10000); // малое основание для стабильности
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

        return false; // составное
    }

    return true; // вероятно простое
}

// Генерация случайного BigInt
static BigInt random_bigint(int bit_length) {
    std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    BigInt result(0);
    for (int i = 0; i < bit_length; i += 4) {
        result = result * BigInt(10);
        result = result + BigInt(rng() % 10);
    }
    return result;
}

// Нахождение обратного по модулю (расширенный алгоритм Евклида)
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
    BigInt p, q;

    // Генерация двух разных простых чисел
    do {
        p = random_bigint(bit_length);
    } while (!is_prime(p));

    do {
        q = random_bigint(bit_length);
    } while (!is_prime(q) || p == q);

    BigInt n = p * q;
    BigInt phi = (p - BigInt(1)) * (q - BigInt(1));
    BigInt e = 65537;

    while (BigInt::gcd(e, phi) != BigInt(1)) {
        e = e + BigInt(2);
    }

    BigInt d = modinv(e, phi);

    pub = {e, n};
    priv = {d, n};
}

BigInt RSA::encrypt(const BigInt& message, const RSAPublicKey& key) {
    return BigInt::modPow(message, key.e, key.n);
}

BigInt RSA::decrypt(const BigInt& cipher, const RSAPrivateKey& key) {
    return BigInt::modPow(cipher, key.d, key.n);
}

BigInt RSA::sign(const BigInt& hash, const RSAPrivateKey& key) {
    return BigInt::modPow(hash, key.d, key.n);
}

bool RSA::verify(const std::string& messageHashHex, const BigInt& signature, const RSAPublicKey& key) {
    // Расшифровываем подпись
    BigInt decryptedHashInt = BigInt::modPow(signature, key.e, key.n);
    std::string decryptedHashHex = decryptedHashInt.toString(16);

    // Дополняем нулями до 64 символов (SHA-256 в hex)
    while (decryptedHashHex.length() < 64)
        decryptedHashHex = "0" + decryptedHashHex;

    return decryptedHashHex == messageHashHex;
}

