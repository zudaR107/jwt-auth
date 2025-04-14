#pragma once
#include <string>
#include <cstdint>
#include "RSA.h"

/**
 * @brief Класс, реализующий создание и проверку JSON Web Token (JWT).
 * 
 * JWT — это компактный URL-безопасный формат, используемый для представления утверждений (claims) 
 * между двумя сторонами. Здесь реализована поддержка токенов с алгоритмом RS256 (RSA + SHA256).
 *
 * Структура токена:
 * - Header: информация об алгоритме подписи и типе ("alg": "RS256", "typ": "JWT")
 * - Payload: полезные данные, включая:
 *   - `sub` — subject (имя пользователя),
 *   - `iat` — время создания (issued at),
 *   - `exp` — время истечения,
 *   - `typ` — тип токена (access или refresh)
 * - Signature: RSA-подпись от (Base64(header) + "." + Base64(payload))
 */
class JWT {
public:
    /**
     * @brief Создаёт access-токен для указанного пользователя.
     * 
     * Алгоритм:
     * 1. Формируется JSON header: {"alg":"RS256","typ":"JWT"}
     * 2. Формируется JSON payload с subject (имя пользователя), временем создания (iat),
     *    временем истечения (exp), и типом токена "access".
     * 3. Оба JSON-объекта кодируются в Base64URL.
     * 4. Выполняется хеширование SHA256 от соединённой строки: `header.payload`
     * 5. Хеш подписывается приватным RSA-ключом.
     * 6. Подпись также кодируется в Base64URL и добавляется к JWT.
     * 
     * @param subject Имя пользователя, для которого создаётся токен
     * @param expirationSeconds Время жизни токена (в секундах)
     * @param privKey Приватный RSA-ключ для подписи
     * @return Сформированный access токен (в виде строки)
     */
    static std::string createAccessToken(const std::string& subject, 
                                         uint64_t expirationSeconds, 
                                         const RSAPrivateKey& privKey);

    /**
     * @brief Проверяет access-токен на подлинность и срок действия.
     * 
     * Алгоритм:
     * 1. Токен разбивается на три части: header, payload, signature.
     * 2. Снова вычисляется SHA256-хеш от `header.payload`.
     * 3. Проверяется RSA-подпись с использованием публичного ключа.
     * 4. Проверяется тип токена ("typ": "access") в payload.
     * 5. Проверяется время истечения.
     * 6. Если всё верно, возвращается имя пользователя (`sub`).
     * 
     * @param token JWT access-токен
     * @param pubKey Публичный ключ для проверки подписи
     * @param outSubject Выходной параметр — имя пользователя из токена
     * @return true, если токен валиден; false — иначе
     */
    static bool verifyAccessToken(const std::string& token, 
                                  const RSAPublicKey& pubKey, 
                                  std::string& outSubject);

    /**
     * @brief Создаёт refresh-токен для указанного пользователя.
     * 
     * Алгоритм аналогичен createAccessToken, но:
     * - В payload указывается тип токена "refresh".
     * - Время жизни устанавливается длиннее, чем у access-токена.
     * 
     * @param subject Имя пользователя
     * @param expirationSeconds Время жизни refresh токена (в секундах)
     * @param privKey Приватный RSA-ключ
     * @return Сформированный refresh токен
     */
    static std::string createRefreshToken(const std::string& subject, 
                                          uint64_t expirationSeconds, 
                                          const RSAPrivateKey& privKey);

    /**
     * @brief Проверяет refresh-токен на подлинность и срок действия.
     * 
     * Алгоритм аналогичен verifyAccessToken, но с проверкой `"typ": "refresh"`.
     * 
     * @param token JWT refresh-токен
     * @param pubKey Публичный RSA-ключ
     * @param outSubject Выходной параметр — имя пользователя
     * @return true, если токен валиден и не просрочен; false — иначе
     */
    static bool verifyRefreshToken(const std::string& token, 
                                   const RSAPublicKey& pubKey, 
                                   std::string& outSubject);
};
