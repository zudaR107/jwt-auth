#pragma once
#include <string>
#include <cstdint>

struct User {
    int id;
    std::string username;
    std::string password;
};

class Database {
public:
    static bool init(const std::string& db_path);
    static bool addUser(const std::string& username, const std::string& password);
    static bool getUser(const std::string& username, User& user_out);

    // Для blacklist-а токенов
    static bool blacklistToken(const std::string& token, uint64_t expires_at);
    static bool isTokenBlacklisted(const std::string& token);
    static bool cleanupBlacklist();
};
