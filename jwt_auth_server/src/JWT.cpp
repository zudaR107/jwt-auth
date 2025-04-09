#include "JWT.h"
#include "Base64URL.h"
#include "SHA256.h"
#include "RSA.h"

#include <ctime>
#include <sstream>
#include <iostream>
//#include <cstdint>

std::string JWT::createToken(const std::string& subject, uint64_t expirationSeconds, const RSAPrivateKey& privKey) {
    // [1] Header
    std::string headerStr = R"({"alg":"RS256","typ":"JWT"})";
    std::string headerEncoded = Base64URL::encode(headerStr);

    // [2] Payload
    uint64_t now = std::time(nullptr);
    uint64_t exp = now + expirationSeconds;

    std::ostringstream payloadStream;
    payloadStream << "{\"sub\":\"" << subject << "\",\"iat\":" << now << ",\"exp\":" << exp << "}";
    std::string payloadEncoded = Base64URL::encode(payloadStream.str());

    std::string message = headerEncoded + "." + payloadEncoded;
    std::string hash = SHA256::hash(message);

    // [3] Signature (RSA + SHA256 = RS256)
    BigInt hashInt(hash, 16);
    BigInt signatureInt = RSA::sign(hashInt, privKey);
    std::string signatureStr = Base64URL::encode(signatureInt.toString(16));

    // [4] Token
    return message + "." + signatureStr;
}

bool JWT::verifyToken(const std::string& token, const RSAPublicKey& pubKey, std::string& outSubject) {
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot == std::string::npos || secondDot == std::string::npos) return false;

    std::string headerB64 = token.substr(0, firstDot);
    std::string payloadB64 = token.substr(firstDot + 1, secondDot - firstDot - 1);
    std::string signatureB64 = token.substr(secondDot + 1);

    std::string message = headerB64 + "." + payloadB64;
    std::string expectedHash = SHA256::hash(message);

    // Декодируем подпись и создаем BigInt
    std::string sigHex = Base64URL::decode(signatureB64);
    BigInt signature(sigHex, 16);

    if (!RSA::verify(expectedHash, signature, pubKey)) {
        std::cerr << "[JWT] Подпись недействительна" << std::endl;
        return false;
    }

    // Декодируем payload и извлекаем subject и exp
    std::string payloadJson = Base64URL::decode(payloadB64);

    size_t subPos = payloadJson.find("\"sub\":\"");
    size_t expPos = payloadJson.find("\"exp\":");

    if (subPos == std::string::npos || expPos == std::string::npos) return false;

    subPos += 7;
    size_t subEnd = payloadJson.find("\"", subPos);
    outSubject = payloadJson.substr(subPos, subEnd - subPos);

    expPos += 6;
    size_t expEnd = payloadJson.find_first_of(",}", expPos);
    std::string expStr = payloadJson.substr(expPos, expEnd - expPos);
    uint64_t exp = std::stoull(expStr);

    if (static_cast<uint64_t>(std::time(nullptr)) > exp) {
        std::cerr << "[JWT] Токен просрочен" << std::endl;
        return false;
    }

    return true;
}


