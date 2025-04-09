#include "SHA256.h"
#include <vector>
#include <array>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>

namespace {
    const std::array<uint32_t, 64> k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    inline uint32_t big_sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    inline uint32_t big_sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    inline uint32_t small_sigma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    inline uint32_t small_sigma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    std::vector<uint8_t> pad(const std::string& input) {
        size_t original_length = input.size();
        uint64_t bit_length = original_length * 8;

        std::vector<uint8_t> padded(input.begin(), input.end());
        padded.push_back(0x80);

        while ((padded.size() + 8) % 64 != 0)
            padded.push_back(0x00);

        for (int i = 7; i >= 0; --i)
            padded.push_back((bit_length >> (i * 8)) & 0xFF);

        return padded;
    }

    uint32_t to_uint32(const uint8_t* bytes) {
        return (bytes[0] << 24) | (bytes[1] << 16) |
               (bytes[2] << 8) | bytes[3];
    }

    void from_uint32(uint32_t val, uint8_t* bytes) {
        bytes[0] = (val >> 24) & 0xFF;
        bytes[1] = (val >> 16) & 0xFF;
        bytes[2] = (val >> 8) & 0xFF;
        bytes[3] = val & 0xFF;
    }
}

std::string SHA256::hash(const std::string& input) {
    std::array<uint32_t, 8> h = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    std::vector<uint8_t> data = pad(input);

    for (size_t i = 0; i < data.size(); i += 64) {
        uint32_t w[64];

        for (int j = 0; j < 16; ++j)
            w[j] = to_uint32(&data[i + j * 4]);

        for (int j = 16; j < 64; ++j)
            w[j] = small_sigma1(w[j - 2]) + w[j - 7] +
                   small_sigma0(w[j - 15]) + w[j - 16];

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_val = h[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t temp1 = h_val + big_sigma1(e) + ch(e, f, g) + k[j] + w[j];
            uint32_t temp2 = big_sigma0(a) + maj(a, b, c);

            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }

    std::ostringstream oss;
    for (auto val : h) {
        oss << std::hex << std::setw(8) << std::setfill('0') << val;
    }

    return oss.str();
}
