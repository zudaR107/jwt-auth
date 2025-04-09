#include "Database.h"
#include "PasswordEncryptor.h"
#include <sqlite3.h>
#include <iostream>

sqlite3* db = nullptr;

bool Database::init(const std::string& db_path) {
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    const char* create_table_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            refresh_token TEXT
        );
    )";

    char* errMsg = nullptr;
    rc = sqlite3_exec(db, create_table_sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << "\n";
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
    const char* sql = "SELECT id, username, password, refresh_token FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        user_out.id = sqlite3_column_int(stmt, 0);
        user_out.username = (const char*)sqlite3_column_text(stmt, 1);
        user_out.password = (const char*)sqlite3_column_text(stmt, 2);
        const unsigned char* token = sqlite3_column_text(stmt, 3);
        user_out.refresh_token = token ? (const char*)token : "";
        found = true;
    }

    sqlite3_finalize(stmt);
    return found;
}

bool Database::updateRefreshToken(int user_id, const std::string& token) {
    const char* sql = "UPDATE users SET refresh_token = ? WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, user_id);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}
