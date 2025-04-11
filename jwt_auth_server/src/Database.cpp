#include "../include/Database.h"
#include "../include/PasswordEncryptor.h"
#include <sqlite3.h>
#include <iostream>
#include <ctime>

sqlite3* db = nullptr;

bool Database::init(const std::string& db_path) {
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    const char* create_users_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    )";

    const char* create_blacklist_sql = R"(
        CREATE TABLE IF NOT EXISTS blacklist (
            token TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );
    )";

    char* errMsg = nullptr;

    rc = sqlite3_exec(db, create_users_sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (users): " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    rc = sqlite3_exec(db, create_blacklist_sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error (blacklist): " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    std::cout << "Database initialized successfully.\n";
    return true;
}

bool Database::addUser(const std::string& username, const std::string& password) {
    std::string hashed = PasswordEncryptor::hashPassword(password);
    const char* sql = "INSERT INTO users (username, password) VALUES (?, ?);";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool Database::getUser(const std::string& username, User& user_out) {
    const char* sql = "SELECT id, username, password FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        user_out.id = sqlite3_column_int(stmt, 0);
        user_out.username = (const char*)sqlite3_column_text(stmt, 1);
        user_out.password = (const char*)sqlite3_column_text(stmt, 2);
        found = true;
    }

    sqlite3_finalize(stmt);
    return found;
}

// ===========================
// BLACKLIST METHODS
// ===========================

bool Database::blacklistToken(const std::string& token, uint64_t expires_at) {
    const char* sql = "INSERT OR IGNORE INTO blacklist (token, expires_at) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(expires_at));

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool Database::isTokenBlacklisted(const std::string& token) {
    const char* sql = "SELECT 1 FROM blacklist WHERE token = ? LIMIT 1;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);

    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

bool Database::cleanupBlacklist() {
    const char* sql = "DELETE FROM blacklist WHERE expires_at < ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(std::time(nullptr)));

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}
