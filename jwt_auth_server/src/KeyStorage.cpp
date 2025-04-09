#include "KeyStorage.h"
#include "SHA256.h"
#include <fstream>
#include <sstream>
#include <iostream>

static const std::string PRIV_FILE = "rsa_private.key";
static const std::string PUB_FILE = "rsa_public.key";

void KeyStorage::saveKeys(const RSAPublicKey& pubKey, const RSAPrivateKey& privKey) {
    // Save private key with SHA256 hash
    std::ofstream privOut(PRIV_FILE);
    if (privOut) {
        std::string content = privKey.d.toString() + ";" + privKey.n.toString();
        std::string hash = SHA256::hash(content);
        privOut << content << "\n" << "hash=" << hash << "\n";
    }

    // Save public key
    std::ofstream pubOut(PUB_FILE);
    if (pubOut) {
        pubOut << pubKey.e.toString() << ";" << pubKey.n.toString() << "\n";
    }
}

bool KeyStorage::loadKeys(RSAPublicKey& pubKey, RSAPrivateKey& privKey) {
    std::ifstream privIn(PRIV_FILE);
    std::ifstream pubIn(PUB_FILE);

    if (!privIn || !pubIn) return false;

    std::string privLine, hashLine;
    if (!std::getline(privIn, privLine) || !std::getline(privIn, hashLine)) return false;

    // validate hash
    std::string expectedHash = SHA256::hash(privLine);
    if (hashLine != "hash=" + expectedHash) {
        std::cerr << "[KeyStorage] Ошибка: контрольная сумма не совпадает. Приватный ключ поврежден." << std::endl;
        return false;
    }

    size_t delimPos = privLine.find(';');
    if (delimPos == std::string::npos) return false;
    std::string dStr = privLine.substr(0, delimPos);
    std::string nStr = privLine.substr(delimPos + 1);

    privKey.d = BigInt(dStr);
    privKey.n = BigInt(nStr);

    // Load public key
    std::string pubLine;
    if (!std::getline(pubIn, pubLine)) return false;

    delimPos = pubLine.find(';');
    if (delimPos == std::string::npos) return false;
    std::string eStr = pubLine.substr(0, delimPos);
    std::string pubNStr = pubLine.substr(delimPos + 1);

    pubKey.e = BigInt(eStr);
    pubKey.n = BigInt(pubNStr);

    return true;
}
