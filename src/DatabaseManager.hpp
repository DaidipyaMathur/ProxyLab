#ifndef DATABASEMANAGER_HPP
#define DATABASEMANAGER_HPP

#include <string>
#include <mutex>
#include "DataTypes.hpp"

struct sqlite3; // Forward declaration for the SQLite handle

class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();

    // Initializes the database, sets the key, and creates the table
    void initialize(const std::string& db_path, const std::string& password);

    // Logs a request/response pair
    void log_transaction(const ParsedHttpData& request, const std::string& raw_req, const ParsedHttpData& response, const std::string& raw_resp);

private:
    sqlite3* db_handle_ = nullptr;
    std::mutex db_mutex_;
};

#endif // DATABASEMANAGER_HPP