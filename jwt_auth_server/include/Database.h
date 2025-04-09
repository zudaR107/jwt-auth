#pragma once
#include <string>

struct User {
    int id;
    std::string username;
    std::string password;
    std::string refresh_token;
};

class Database {
public:
    static bool init(const std::string& db_path);
    static bool addUser(const std::string& username, const std::string& password);
    static bool getUser(const std::string& username, User& user_out);
    static bool updateRefreshToken(int user_id, const std::string& token);
};
