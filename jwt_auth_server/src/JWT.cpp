#include "../include/JWT.h"
#include "../include/Base64URL.h"
#include "../include/SHA256.h"
#include "../include/RSA.h"

#include <ctime>
#include <sstream>
#include <iostream>
#include <iomanip>

std::string JWT::createAccessToken(const std::string& subject, uint64_t expirationSeconds, const RSAPrivateKey& privKey) {
    std::string headerStr = R"({"alg":"RS256","typ":"JWT"})";
    std::string headerEncoded = Base64URL::encode(headerStr);

    uint64_t now = std::time(nullptr);
    uint64_t exp = now + expirationSeconds;

    std::ostringstream payloadStream;
    payloadStream << "{\"sub\":\"" << subject << "\",\"iat\":" << now
                  << ",\"exp\":" << exp << ",\"typ\":\"access\"}";

    std::string payloadEncoded = Base64URL::encode(payloadStream.str());

    std::string message = headerEncoded + "." + payloadEncoded;
    std::string hash = SHA256::hash(message);

    BigInt hashInt(hash, 16);
    BigInt signatureInt = RSA::sign(hashInt, privKey);
    std::string signatureStr = Base64URL::encode(signatureInt.toString(16));

    std::string token = message + "." + signatureStr;

    std::cout << "[JWT::createAccessToken] ---" << std::endl;
    std::cout << "Header JSON:   " << headerStr << std::endl;
    std::cout << "Payload JSON:  " << payloadStream.str() << std::endl;
    std::cout << "Header Encoded:  " << headerEncoded << std::endl;
    std::cout << "Payload Encoded: " << payloadEncoded << std::endl;
    std::cout << "Message (header.payload): " << message << std::endl;
    std::cout << "SHA256 Hash: " << hash << std::endl;
    std::cout << "Signature (hex): " << signatureInt.toString(16) << std::endl;
    std::cout << "Access Token: " << token << std::endl;

    return token;
}

std::string JWT::createRefreshToken(const std::string& subject, uint64_t expirationSeconds, const RSAPrivateKey& privKey) {
    std::string headerStr = R"({"alg":"RS256","typ":"JWT"})";
    std::string headerEncoded = Base64URL::encode(headerStr);

    uint64_t now = std::time(nullptr);
    uint64_t exp = now + expirationSeconds;

    std::ostringstream payloadStream;
    payloadStream << "{\"sub\":\"" << subject << "\",\"iat\":" << now
                  << ",\"exp\":" << exp << ",\"typ\":\"refresh\"}";

    std::string payloadEncoded = Base64URL::encode(payloadStream.str());

    std::string message = headerEncoded + "." + payloadEncoded;
    std::string hash = SHA256::hash(message);

    BigInt hashInt(hash, 16);
    BigInt signatureInt = RSA::sign(hashInt, privKey);
    std::string signatureStr = Base64URL::encode(signatureInt.toString(16));

    std::string token = message + "." + signatureStr;

    std::cout << "[JWT::createRefreshToken] ---" << std::endl;
    std::cout << "Header JSON:   " << headerStr << std::endl;
    std::cout << "Payload JSON:  " << payloadStream.str() << std::endl;
    std::cout << "Header Encoded:  " << headerEncoded << std::endl;
    std::cout << "Payload Encoded: " << payloadEncoded << std::endl;
    std::cout << "Message (header.payload): " << message << std::endl;
    std::cout << "SHA256 Hash: " << hash << std::endl;
    std::cout << "Signature (hex): " << signatureInt.toString(16) << std::endl;
    std::cout << "Refresh Token: " << token << std::endl;

    return token;
}

bool JWT::verifyAccessToken(const std::string& token, const RSAPublicKey& pubKey, std::string& outSubject) {
    std::cout << "[JWT::verifyAccessToken] ---" << std::endl;
    std::cout << "Received token: " << token << std::endl;

    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot == std::string::npos || secondDot == std::string::npos) return false;

    std::string headerB64 = token.substr(0, firstDot);
    std::string payloadB64 = token.substr(firstDot + 1, secondDot - firstDot - 1);
    std::string signatureB64 = token.substr(secondDot + 1);

    std::string message = headerB64 + "." + payloadB64;
    std::string expectedHash = SHA256::hash(message);

    std::string sigHex = Base64URL::decode(signatureB64);
    BigInt signature(sigHex, 16);

    if (!RSA::verify(expectedHash, signature, pubKey)) {
        std::cerr << "[JWT] Подпись access токена недействительна" << std::endl;
        return false;
    }

    std::string payloadJson = Base64URL::decode(payloadB64);
    std::cout << "Decoded payload: " << payloadJson << std::endl;

    if (payloadJson.find("\"typ\":\"access\"") == std::string::npos) {
        std::cerr << "[JWT] Токен не является access" << std::endl;
        return false;
    }

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

    std::cout << "Subject: " << outSubject << std::endl;
    std::cout << "Expiration: " << exp << ", now: " << std::time(nullptr) << std::endl;

    if (static_cast<uint64_t>(std::time(nullptr)) > exp) {
        std::cerr << "[JWT] Access токен просрочен" << std::endl;
        return false;
    }

    return true;
}

bool JWT::verifyRefreshToken(const std::string& token, const RSAPublicKey& pubKey, std::string& outSubject) {
    std::cout << "[JWT::verifyRefreshToken] ---" << std::endl;
    std::cout << "Received token: " << token << std::endl;

    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot == std::string::npos || secondDot == std::string::npos) return false;

    std::string headerB64 = token.substr(0, firstDot);
    std::string payloadB64 = token.substr(firstDot + 1, secondDot - firstDot - 1);
    std::string signatureB64 = token.substr(secondDot + 1);

    std::string message = headerB64 + "." + payloadB64;
    std::string expectedHash = SHA256::hash(message);

    std::string sigHex = Base64URL::decode(signatureB64);
    BigInt signature(sigHex, 16);

    if (!RSA::verify(expectedHash, signature, pubKey)) {
        std::cerr << "[JWT] Refresh подпись недействительна" << std::endl;
        return false;
    }

    std::string payloadJson = Base64URL::decode(payloadB64);
    std::cout << "Decoded payload: " << payloadJson << std::endl;

    if (payloadJson.find("\"typ\":\"refresh\"") == std::string::npos) {
        std::cerr << "[JWT] Токен не является refresh" << std::endl;
        return false;
    }

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

    std::cout << "Subject: " << outSubject << std::endl;
    std::cout << "Expiration: " << exp << ", now: " << std::time(nullptr) << std::endl;

    if (static_cast<uint64_t>(std::time(nullptr)) > exp) {
        std::cerr << "[JWT] Refresh токен просрочен" << std::endl;
        return false;
    }

    return true;
}
