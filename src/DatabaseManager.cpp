#include "DatabaseManager.hpp"
#include <sqlcipher/sqlite3.h>
#include <stdexcept>
#include <iostream>
#include <sstream>

DatabaseManager::DatabaseManager() {}

DatabaseManager::~DatabaseManager() {
    if (db_handle_) {
        sqlite3_close(db_handle_);
    }
}

void DatabaseManager::initialize(const std::string& db_path, const std::string& password) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    // 1. Open the database file
    if (sqlite3_open(db_path.c_str(), &db_handle_) != SQLITE_OK) {
        throw std::runtime_error("Failed to open database: " + std::string(sqlite3_errmsg(db_handle_)));
    }

    // 2. Set the encryption key (This is the SQLCipher magic)
    std::string set_key_pragma = "PRAGMA key = '" + password + "';";
    if (sqlite3_exec(db_handle_, set_key_pragma.c_str(), 0, 0, 0) != SQLITE_OK) {
        throw std::runtime_error("Failed to set database encryption key: " + std::string(sqlite3_errmsg(db_handle_)));
    }

    // 3. Create the history table if it doesn't exist
    const char* create_table_sql = 
        "CREATE TABLE IF NOT EXISTS history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "method TEXT, "
        "url TEXT, "
        "status_code INTEGER, "
        "request_raw TEXT, "
        "response_raw TEXT);";

    if (sqlite3_exec(db_handle_, create_table_sql, 0, 0, 0) != SQLITE_OK) {
        throw std::runtime_error("Failed to create history table: " + std::string(sqlite3_errmsg(db_handle_)));
    }
     std::cout << "Database initialized successfully at " << db_path << std::endl;
}

void DatabaseManager::log_transaction(const ParsedHttpData& request,const std::string& raw_req, const ParsedHttpData& response, const std::string& raw_resp) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* insert_sql = "INSERT INTO history (method, url, status_code, request_raw, response_raw) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db_handle_, insert_sql, -1, &stmt, 0) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_handle_) << std::endl;
        return;
    }

    // Extract method and URL from request start_line
    std::string method, url;
    std::istringstream iss(request.start_line);
    iss >> method >> url;

    // Extract status code from response start_line
    int status_code = 0;
    std::string http_version;
    std::istringstream iss_resp(response.start_line);
    iss_resp >> http_version >> status_code;

    // For simplicity, we'll just store the raw data for now.
    // Reconstructing the full raw text is left as an exercise.
    sqlite3_bind_text(stmt, 4, raw_req.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, raw_resp.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt, 1, method.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, url.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, status_code);
    sqlite3_bind_text(stmt, 4, raw_req.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, raw_resp.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_handle_) << std::endl;
    }

    sqlite3_finalize(stmt);
}