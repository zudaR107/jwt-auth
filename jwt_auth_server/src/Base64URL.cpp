#include "../include/Base64URL.h"
#include <string>
#include <vector>
#include <iostream>

static const char* base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string Base64URL::encode(const std::string& input) {
    std::cout << "[Base64URL::encode] Входная строка: " << input << std::endl;

    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            char ch = base64_chars[(val >> valb) & 0x3F];
            encoded.push_back(ch);
            valb -= 6;
        }
    }

    if (valb > -6) {
        char ch = base64_chars[((val << 8) >> (valb + 8)) & 0x3F];
        encoded.push_back(ch);
    }

    // Преобразование в Base64URL
    for (char& c : encoded) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    while (!encoded.empty() && encoded.back() == '=')
        encoded.pop_back();

    std::cout << "[Base64URL::encode] Кодированная строка (Base64URL): " << encoded << std::endl;
    return encoded;
}

std::string Base64URL::decode(const std::string& input) {
    std::cout << "[Base64URL::decode] Входная строка (Base64URL): " << input << std::endl;

    std::string b64 = input;
    for (char& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }

    while (b64.size() % 4 != 0)
        b64 += '=';

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : b64) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            char ch = char((val >> valb) & 0xFF);
            out.push_back(ch);
            valb -= 8;
        }
    }

    std::cout << "[Base64URL::decode] Декодированная строка: " << out << std::endl;
    return out;
}
