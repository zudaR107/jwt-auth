#include "../include/HttpServer.h"
#include "../include/extern/httplib.h"
#include "../include/Database.h"
#include "../include/PasswordEncryptor.h"
#include "../include/JWT.h"
#include "../include/KeyStorage.h"

#include <iostream>
#include <string>

static std::string extractField(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\"";
    size_t key_pos = json.find(pattern);
    if (key_pos == std::string::npos) return "";

    size_t colon_pos = json.find(':', key_pos);
    if (colon_pos == std::string::npos) return "";

    size_t quote_start = json.find('"', colon_pos + 1);
    if (quote_start == std::string::npos) return "";

    size_t quote_end = json.find('"', quote_start + 1);
    if (quote_end == std::string::npos) return "";

    return json.substr(quote_start + 1, quote_end - quote_start - 1);
}

void HttpServer::start(int port) {
    httplib::Server server;

    server.Post("/register", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "[REGISTER] Получен запрос: " << req.body << std::endl;

        std::string username = extractField(req.body, "username");
        std::string password = extractField(req.body, "password");

        if (username.empty() || password.empty()) {
            std::cerr << "[REGISTER] Отсутствует username или password" << std::endl;
            res.status = 400;
            res.set_content("Missing 'username' or 'password'", "text/plain");
            return;
        }

        std::cout << "[REGISTER] Имя пользователя: " << username << std::endl;

        if (!Database::addUser(username, password)) {
            std::cerr << "[REGISTER] Пользователь уже существует" << std::endl;
            res.status = 409;
            res.set_content("Username already exists", "text/plain");
            return;
        }

        std::cout << "[REGISTER] Регистрация успешна" << std::endl;
        res.status = 201;
        res.set_content("User registered successfully", "text/plain");
    });

    server.Post("/login", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "[LOGIN] Получен запрос: " << req.body << std::endl;

        std::string username = extractField(req.body, "username");
        std::string password = extractField(req.body, "password");

        if (username.empty() || password.empty()) {
            std::cerr << "[LOGIN] Отсутствует username или password" << std::endl;
            res.status = 400;
            res.set_content("Missing 'username' or 'password'", "text/plain");
            return;
        }

        std::cout << "[LOGIN] Имя пользователя: " << username << std::endl;

        User user;
        if (!Database::getUser(username, user)) {
            std::cerr << "[LOGIN] Пользователь не найден в базе данных" << std::endl;
            res.status = 401;
            res.set_content("Invalid credentials", "text/plain");
            return;
        }

        std::string hashedInput = PasswordEncryptor::hashPassword(password);
        std::cout << "[LOGIN] Введённый пароль (хеш): " << hashedInput << std::endl;
        std::cout << "[LOGIN] Хеш пароля из базы:      " << user.password << std::endl;

        if (hashedInput != user.password) {
            std::cerr << "[LOGIN] Неверный пароль" << std::endl;
            res.status = 401;
            res.set_content("Invalid credentials", "text/plain");
            return;
        }

        RSAPublicKey pubKey;
        RSAPrivateKey privKey;
        if (!KeyStorage::loadKeys(pubKey, privKey)) {
            std::cerr << "[LOGIN] Ошибка загрузки ключей" << std::endl;
            res.status = 500;
            res.set_content("Key error", "text/plain");
            return;
        }

        std::string accessToken = JWT::createAccessToken(username, 60 * 1, privKey);      // 1 минута
        std::string refreshToken = JWT::createRefreshToken(username, 60 * 60, privKey);   // 60 минут

        std::cout << "[LOGIN] Сгенерирован Access токен:" << std::endl << accessToken << std::endl;
        std::cout << "[LOGIN] Сгенерирован Refresh токен:" << std::endl << refreshToken << std::endl;

        std::string response = "{";
        response += "\"access_token\":\"" + accessToken + "\",";
        response += "\"refresh_token\":\"" + refreshToken + "\"";
        response += "}";

        res.set_content(response, "application/json");
        std::cout << "[LOGIN] Ответ отправлен клиенту\n" << std::endl;
    });

    std::cout << "[HttpServer] Сервер запущен на порту " << port << std::endl;
    server.listen("0.0.0.0", port);
}
