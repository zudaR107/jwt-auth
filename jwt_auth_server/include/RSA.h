#pragma once
#include "BigInt.h"

/**
 * @brief Структура для хранения открытого (публичного) ключа RSA.
 * 
 * Открытый ключ состоит из:
 * - e — публичная экспонента;
 * - n — модуль (произведение двух больших простых чисел p и q).
 */
struct RSAPublicKey {
    BigInt e; ///< Публичная экспонента
    BigInt n; ///< Модуль
};

/**
 * @brief Структура для хранения закрытого (приватного) ключа RSA.
 * 
 * Приватный ключ состоит из:
 * - d — приватная экспонента;
 * - n — тот же модуль, что и в открытом ключе.
 */
struct RSAPrivateKey {
    BigInt d; ///< Приватная экспонента
    BigInt n; ///< Модуль
};

/**
 * @brief Класс, реализующий основные операции алгоритма RSA.
 *
 * Включает в себя генерацию ключей, шифрование/дешифрование, подпись и верификацию.
 */
class RSA {
public:
    /**
     * @brief Генерация пары RSA-ключей.
     *
     * Алгоритм:
     * 1. Выбираются два больших случайных простых числа `p` и `q`.
     * 2. Вычисляется `n = p * q`.
     * 3. Вычисляется `phi(n) = (p - 1) * (q - 1)`.
     * 4. Выбирается публичная экспонента `e`, обычно 65537, такая, что `gcd(e, phi) == 1`.
     * 5. Вычисляется приватная экспонента `d`, такая что `d * e ≡ 1 (mod phi(n))` — обратное по модулю.
     *
     * @param[out] pub Структура, в которую будет записан открытый ключ
     * @param[out] priv Структура, в которую будет записан приватный ключ
     * @param bit_length Размер случайных простых чисел (по умолчанию 64 бита)
     */
    static void generate_keys(RSAPublicKey& pub, RSAPrivateKey& priv, int bit_length = 64);

    /**
     * @brief Шифрует сообщение с использованием открытого ключа.
     *
     * Применяется формула: `cipher = message^e mod n`.
     *
     * @param message Открытое сообщение
     * @param key Открытый ключ
     * @return Зашифрованное сообщение
     */
    static BigInt encrypt(const BigInt& message, const RSAPublicKey& key);

    /**
     * @brief Расшифровывает сообщение с использованием приватного ключа.
     *
     * Применяется формула: `message = cipher^d mod n`.
     *
     * @param cipher Зашифрованное сообщение
     * @param key Приватный ключ
     * @return Расшифрованное сообщение
     */
    static BigInt decrypt(const BigInt& cipher, const RSAPrivateKey& key);

    /**
     * @brief Создаёт цифровую подпись хеша сообщения.
     *
     * Применяется формула: `signature = hash^d mod n`.
     *
     * @param hash Хеш сообщения, представленный как число
     * @param key Приватный ключ
     * @return Подпись сообщения
     */
    static BigInt sign(const BigInt& hash, const RSAPrivateKey& key);

    /**
     * @brief Проверяет цифровую подпись по хешу сообщения.
     *
     * Выполняется:
     * 1. `hash' = signature^e mod n`
     * 2. Сравнение `hash' == hash`, где `hash` — это ожидаемый хеш в шестнадцатеричном виде.
     *
     * @param messageHashHex Ожидаемый хеш сообщения (в hex)
     * @param signature Подпись
     * @param key Открытый ключ
     * @return true, если подпись валидна; false — иначе
     */
    static bool verify(const std::string& messageHashHex,
                       const BigInt& signature,
                       const RSAPublicKey& key);
};
