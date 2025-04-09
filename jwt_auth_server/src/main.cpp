#include <iostream>
#include "JWT.h"
#include "RSA.h"
#include "KeyStorage.h"
#include "Base64URL.h"

int main() {
    RSAPublicKey pubKey;
    RSAPrivateKey privKey;

    if (!KeyStorage::loadKeys(pubKey, privKey)) {
        std::cout << "[main] Ключи не найдены. Генерация..." << std::endl;
        RSA::generate_keys(pubKey, privKey, 256);
        KeyStorage::saveKeys(pubKey, privKey);
    }

    // 1. Генерация корректного токена
    std::string originalToken = JWT::createToken("ZudaR", 60, privKey);
    std::cout << "Оригинальный JWT:\n" << originalToken << "\n\n";

    std::string subject;
    bool isValid = JWT::verifyToken(originalToken, pubKey, subject);
    std::cout << "Проверка оригинального токена: " << (isValid ? "валиден" : "НЕвалиден") << "\n\n";

    // 2. Подделка токена: меняем payload
    size_t firstDot = originalToken.find('.');
    size_t secondDot = originalToken.find('.', firstDot + 1);

    std::string headerB64 = originalToken.substr(0, firstDot);
    std::string payloadB64 = originalToken.substr(firstDot + 1, secondDot - firstDot - 1);
    std::string signatureB64 = originalToken.substr(secondDot + 1);

    std::string decodedPayload = Base64URL::decode(payloadB64);
    std::cout << "Исходный payload: " << decodedPayload << "\n";

    // Меняем sub на "admin"
    size_t subPos = decodedPayload.find("\"sub\":\"");
    if (subPos != std::string::npos) {
        size_t endPos = decodedPayload.find("\"", subPos + 7);
        decodedPayload.replace(subPos + 7, endPos - (subPos + 7), "admin");
    }

    std::string tamperedPayloadB64 = Base64URL::encode(decodedPayload);
    std::string tamperedToken = headerB64 + "." + tamperedPayloadB64 + "." + signatureB64;

    std::cout << "\nПодделанный JWT:\n" << tamperedToken << "\n\n";

    // 3. Проверка подделанного токена
    bool isValidTampered = JWT::verifyToken(tamperedToken, pubKey, subject);
    std::cout << "Проверка подделанного токена: " << (isValidTampered ? "валиден" : "НЕвалиден") << "\n";

    return 0;
}
