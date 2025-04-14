#include "../include/HttpServer.h"
#include "../include/extern/httplib.h"
#include "../include/Database.h"
#include "../include/PasswordEncryptor.h"
#include "../include/JWT.h"
#include "../include/KeyStorage.h"
#include "../include/Base64URL.h"

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

    server.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::cout << "[LOGGER] " << req.method << " " << req.path << " -> " << res.status << "\n";
    });
    
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

    server.Post("/refresh", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "\n[SERVER] --- /refresh endpoint called ---\n";
    
        if (!req.has_header("Authorization")) {
            std::cerr << "[ERROR] Missing Authorization header\n";
            res.status = 400;
            res.set_content("Missing Authorization header", "text/plain");
            return;
        }
    
        std::string authHeader = req.get_header_value("Authorization");
        std::cout << "[HEADER] Authorization: " << authHeader << "\n";
    
        std::string prefix = "Bearer ";
        if (authHeader.rfind(prefix, 0) != 0) {
            std::cerr << "[ERROR] Authorization header must start with 'Bearer '\n";
            res.status = 400;
            res.set_content("Invalid Authorization header format", "text/plain");
            return;
        }
    
        std::string refreshToken = authHeader.substr(prefix.size());
        std::cout << "[PARSE] Extracted refresh token: " << refreshToken << "\n";
    
        RSAPublicKey pubKey;
        RSAPrivateKey privKey;
        if (!KeyStorage::loadKeys(pubKey, privKey)) {
            std::cerr << "[ERROR] Failed to load RSA keys from storage\n";
            res.status = 500;
            res.set_content("Key error", "text/plain");
            return;
        }
    
        std::string username;
        std::cout << "[VERIFY] Verifying refresh token...\n";
        if (!JWT::verifyRefreshToken(refreshToken, pubKey, username)) {
            std::cerr << "[ERROR] Invalid or expired refresh token\n";
            res.status = 401;
            res.set_content("Invalid or expired refresh token", "text/plain");
            return;
        }
    
        std::cout << "[JWT] Refresh token is valid.\n";
        std::cout << "[JWT] Extracted subject (username): " << username << "\n";
    
        if (Database::isTokenBlacklisted(refreshToken)) {
            std::cerr << "[SECURITY] Refresh token is blacklisted. Rejected.\n";
            res.status = 403;
            res.set_content("Refresh token is blacklisted", "text/plain");
            return;
        }
    
        std::cout << "[JWT] Token is not in blacklist. Proceeding to generate new access token...\n";
    
        std::string newAccessToken = JWT::createAccessToken(username, 60, privKey);  // 1 минута
        std::cout << "[JWT] New access token generated:\n" << newAccessToken << "\n";
    
        std::string response = "{";
        response += "\"access_token\":\"" + newAccessToken + "\"";
        response += "}";
    
        std::cout << "[RESPONSE] JSON: " << response << "\n";
        std::cout << "[SERVER] --- /refresh complete ---\n";
    
        res.set_content(response, "application/json");
    });    
    
    server.Get("/secure/data", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "\n[SERVER] --- /secure/data endpoint called ---\n";
    
        // [1] Проверяем заголовок Authorization
        auto authHeaderIt = req.headers.find("Authorization");
        if (authHeaderIt == req.headers.end()) {
            std::cerr << "[ERROR] Missing 'Authorization' header\n";
            res.status = 401;
            res.set_content("Missing 'Authorization' header", "text/plain");
            return;
        }
    
        std::string authHeader = authHeaderIt->second;
        std::cout << "[HEADER] Authorization: " << authHeader << "\n";
    
        if (authHeader.find("Bearer ") != 0) {
            std::cerr << "[ERROR] Invalid Authorization format (should start with 'Bearer ')\n";
            res.status = 400;
            res.set_content("Invalid Authorization format", "text/plain");
            return;
        }
    
        std::string accessToken = authHeader.substr(7);
        std::cout << "[TOKEN] Extracted access token: " << accessToken << "\n";
    
        // [2] Загружаем ключи
        RSAPublicKey pubKey;
        RSAPrivateKey privKey; // не нужен здесь, но оставим на случай доработок
        if (!KeyStorage::loadKeys(pubKey, privKey)) {
            std::cerr << "[ERROR] Failed to load RSA keys\n";
            res.status = 500;
            res.set_content("Key error", "text/plain");
            return;
        }
    
        // [3] Проверяем токен
        std::string subject;
        std::cout << "[VERIFY] Verifying access token...\n";
        if (!JWT::verifyAccessToken(accessToken, pubKey, subject)) {
            std::cerr << "[ERROR] Invalid or expired access token\n";
            res.status = 401;
            res.set_content("Invalid or expired access token", "text/plain");
            return;
        }
    
        std::cout << "[JWT] Access token is valid.\n";
        std::cout << "[JWT] Extracted subject (username): " << subject << "\n";
    
        // [4] Возвращаем защищённые данные
        std::string secureData = "{ \"data\": \"Secret message for " + subject + "\" }";
        std::cout << "[RESPONSE] Sending secure data: " << secureData << "\n";
        std::cout << "[SERVER] --- /secure/data complete ---\n";
    
        res.set_content(secureData, "application/json");
    });
    
    server.Post("/logout", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "\n[SERVER] --- /logout endpoint called ---\n";
    
        if (!req.has_header("Authorization")) {
            std::cerr << "[ERROR] Missing Authorization header\n";
            res.status = 400;
            res.set_content("Missing Authorization header", "text/plain");
            return;
        }
    
        std::string authHeader = req.get_header_value("Authorization");
        std::cout << "[HEADER] Authorization: " << authHeader << "\n";
    
        std::string prefix = "Bearer ";
        if (authHeader.rfind(prefix, 0) != 0) {
            std::cerr << "[ERROR] Authorization header must start with 'Bearer '\n";
            res.status = 400;
            res.set_content("Invalid Authorization header format", "text/plain");
            return;
        }
    
        std::string refreshToken = authHeader.substr(prefix.size());
        std::cout << "[INPUT] Extracted refresh token: " << refreshToken << "\n";
    
        RSAPublicKey pubKey;
        RSAPrivateKey privKey;
        if (!KeyStorage::loadKeys(pubKey, privKey)) {
            std::cerr << "[ERROR] Failed to load keys\n";
            res.status = 500;
            res.set_content("Key error", "text/plain");
            return;
        }
    
        std::string subject;
        std::cout << "[VERIFY] Verifying refresh token...\n";
    
        if (!JWT::verifyRefreshToken(refreshToken, pubKey, subject)) {
            std::cerr << "[ERROR] Invalid or expired refresh token\n";
            res.status = 401;
            res.set_content("Invalid or expired refresh token", "text/plain");
            return;
        }
    
        std::cout << "[JWT] Token is valid. Subject: " << subject << "\n";
    
        // ====== Вытаскиваем expires_at из payload ======
        std::string payloadB64 = refreshToken.substr(
            refreshToken.find('.') + 1,
            refreshToken.rfind('.') - refreshToken.find('.') - 1
        );
        std::string payloadJson = Base64URL::decode(payloadB64);
    
        size_t expPos = payloadJson.find("\"exp\":");
        if (expPos == std::string::npos) {
            std::cerr << "[ERROR] Cannot extract exp from token\n";
            res.status = 400;
            res.set_content("Invalid token payload", "text/plain");
            return;
        }
    
        expPos += 6;
        size_t expEnd = payloadJson.find_first_of(",}", expPos);
        uint64_t expTime = std::stoull(payloadJson.substr(expPos, expEnd - expPos));
    
        std::cout << "[BLACKLIST] Extracted exp time: " << expTime << "\n";
    
        if (!Database::blacklistToken(refreshToken, expTime)) {
            std::cerr << "[ERROR] Failed to blacklist token\n";
            res.status = 500;
            res.set_content("Database error", "text/plain");
            return;
        }
    
        std::cout << "[BLACKLIST] Token successfully blacklisted\n";
        std::cout << "[SERVER] --- /logout completed ---\n";
    
        res.set_content("Logged out successfully", "text/plain");
    });            

    std::cout << "[HttpServer] Сервер запущен на порту " << port << std::endl;
    server.listen("0.0.0.0", port);
}
