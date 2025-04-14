#pragma once
#include <string>
#include <cstdint>

/**
 * @brief Структура, представляющая пользователя из базы данных.
 */
struct User {
    int id;                     ///< Уникальный идентификатор пользователя в таблице.
    std::string username;       ///< Имя пользователя.
    std::string password;       ///< Хеш пароля (уже захеширован).
};

/**
 * @brief Класс-обёртка для работы с SQLite-базой данных.
 *
 * Обеспечивает доступ к таблице пользователей и таблице заблокированных (blacklisted) токенов.
 * Используется для реализации регистрации, авторизации, выхода из системы и защиты от повторного использования refresh токенов.
 */
class Database {
public:
    /**
     * @brief Инициализирует подключение к SQLite-базе данных.
     *
     * Создаёт при необходимости две таблицы:
     * - users(id, username, password)
     * - blacklist(token, expires_at)
     *
     * @param db_path Путь к файлу базы данных.
     * @return true, если инициализация прошла успешно; false в случае ошибки.
     */
    static bool init(const std::string& db_path);

    /**
     * @brief Добавляет нового пользователя в таблицу users.
     *
     * Перед вставкой хеширует пароль.
     *
     * @param username Имя пользователя.
     * @param password Обычный текстовый пароль (будет захеширован).
     * @return true, если пользователь успешно добавлен; false, если уже существует или произошла ошибка.
     */
    static bool addUser(const std::string& username, const std::string& password);

    /**
     * @brief Получает пользователя из базы данных по имени.
     *
     * Если пользователь найден, возвращает его через user_out.
     *
     * @param username Имя пользователя.
     * @param user_out Объект, в который будут загружены данные.
     * @return true, если пользователь найден; false в противном случае.
     */
    static bool getUser(const std::string& username, User& user_out);

    // ===== Методы для работы с blacklist токенов =====

    /**
     * @brief Добавляет токен в таблицу blacklist (например, при logout).
     *
     * Используется для блокировки refresh токена до момента его истечения.
     *
     * @param token Строковое представление JWT токена.
     * @param expires_at Метка времени, когда токен истекает (UNIX-время).
     * @return true, если вставка прошла успешно или токен уже есть; false — в случае ошибки.
     */
    static bool blacklistToken(const std::string& token, uint64_t expires_at);

    /**
     * @brief Проверяет, содержится ли токен в blacklist.
     *
     * Вызывается, чтобы убедиться, что refresh токен не был отозван.
     *
     * @param token Проверяемый JWT токен.
     * @return true, если токен есть в blacklist; false, если его нет.
     */
    static bool isTokenBlacklisted(const std::string& token);

    /**
     * @brief Удаляет все устаревшие токены из blacklist (истёкшие по времени).
     *
     * Вызывается периодически для очистки таблицы и экономии ресурсов.
     *
     * @return true, если удаление прошло успешно; false — при ошибке выполнения запроса.
     */
    static bool cleanupBlacklist();
};
