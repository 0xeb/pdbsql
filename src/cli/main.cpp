/**
 * pdbsql CLI - SQL interface to PDB files
 *
 * Usage:
 *   pdbsql <pdb_file>                      Dump symbol counts
 *   pdbsql <pdb_file> "<query>"            Execute SQL query (local)
 *   pdbsql <pdb_file> -q "<query>"         Execute SQL query (local)
 *   pdbsql <pdb_file> -i                   Interactive mode (local)
 *   pdbsql <pdb_file> --server [port]      Start server mode (default: 13337)
 *   pdbsql --remote host:port -q "<query>" Execute SQL query (remote)
 *   pdbsql --remote host:port -i           Interactive mode (remote)
 *
 * Examples:
 *   pdbsql test.pdb "SELECT name, rva FROM functions LIMIT 10"
 *   pdbsql test.pdb --server 13337
 *   pdbsql --remote localhost:13337 -q "SELECT * FROM functions"
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <vector>
#include <algorithm>

// Socket client for remote mode (no DIA dependency)
#include <xsql/socket/client.hpp>

//=============================================================================
// Table Printing (shared between remote and local modes)
//=============================================================================

struct TablePrinter {
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
    std::vector<size_t> widths;

    void set_columns(const std::vector<std::string>& cols) {
        columns = cols;
        widths.resize(cols.size(), 0);
        for (size_t i = 0; i < cols.size(); i++) {
            widths[i] = (std::max)(widths[i], cols[i].length());
        }
    }

    void add_row(const std::vector<std::string>& row) {
        for (size_t i = 0; i < row.size() && i < widths.size(); i++) {
            widths[i] = (std::max)(widths[i], row[i].length());
        }
        rows.push_back(row);
    }

    void add_row(int argc, char** argv, char** colNames) {
        if (columns.empty()) {
            columns.reserve(argc);
            widths.resize(argc, 0);
            for (int i = 0; i < argc; i++) {
                columns.push_back(colNames[i] ? colNames[i] : "");
                widths[i] = (std::max)(widths[i], columns[i].length());
            }
        }

        std::vector<std::string> row;
        row.reserve(argc);
        for (int i = 0; i < argc; i++) {
            std::string val = argv[i] ? argv[i] : "NULL";
            row.push_back(val);
            widths[i] = (std::max)(widths[i], val.length());
        }
        rows.push_back(std::move(row));
    }

    void print() {
        if (columns.empty()) return;

        // Header separator
        std::string sep = "+";
        for (size_t w : widths) {
            sep += std::string(w + 2, '-') + "+";
        }

        // Header
        std::cout << sep << "\n| ";
        for (size_t i = 0; i < columns.size(); i++) {
            std::cout << std::left;
            std::cout.width(widths[i]);
            std::cout << columns[i] << " | ";
        }
        std::cout << "\n" << sep << "\n";

        // Rows
        for (const auto& row : rows) {
            std::cout << "| ";
            for (size_t i = 0; i < row.size(); i++) {
                std::cout << std::left;
                std::cout.width(widths[i]);
                std::cout << row[i] << " | ";
            }
            std::cout << "\n";
        }
        std::cout << sep << "\n";
        std::cout << rows.size() << " row(s)\n";
    }
};

//=============================================================================
// Remote Mode - Pure socket client (NO DIA/COM DEPENDENCIES)
//=============================================================================

void print_remote_result(const xsql::socket::RemoteResult& qr) {
    if (qr.rows.empty() && qr.columns.empty()) {
        std::cout << "OK\n";
        return;
    }
    TablePrinter printer;
    printer.set_columns(qr.columns);
    for (const auto& row : qr.rows) {
        printer.add_row(row.values);
    }
    printer.print();
}

int run_remote_mode(const std::string& host, int port,
                    const std::string& query, const std::string& auth_token,
                    bool interactive) {
    std::cerr << "Connecting to " << host << ":" << port << "..." << std::endl; 
    xsql::socket::Client client;
    if (!auth_token.empty()) {
        client.set_auth_token(auth_token);
    }
    if (!client.connect(host, port)) {
        std::cerr << "Error: " << client.error() << std::endl;
        return 1;
    }
    std::cerr << "Connected." << std::endl;

    int result = 0;

    if (!query.empty()) {
        // Single query
        auto qr = client.query(query);
        if (qr.success) {
            print_remote_result(qr);
        } else {
            std::cerr << "Error: " << qr.error << "\n";
            result = 1;
        }
    } else if (interactive) {
        // Interactive REPL (remote)
        std::string line;
        std::string stmt;
        std::cout << "PDBSQL Remote Interactive Mode (" << host << ":" << port << ")\n"
                  << "Type .quit to exit\n\n";

        while (true) {
            std::cout << (stmt.empty() ? "pdbsql> " : "   ...> ");
            std::cout.flush();
            if (!std::getline(std::cin, line)) break;
            if (line.empty()) continue;

            if (stmt.empty() && line[0] == '.') {
                if (line == ".quit" || line == ".exit") break;
                if (line == ".tables") {
                    auto qr = client.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
                    if (qr.success) {
                        std::cout << "Tables:\n";
                        for (const auto& row : qr.rows) {
                            std::cout << "  " << row[0] << "\n";
                        }
                    }
                    continue;
                }
                if (line == ".help") {
                    std::cout << R"(
Commands:
  .tables             List all tables
  .quit / .exit       Exit interactive mode
  .help               Show this help

SQL queries end with semicolon (;)
)" << std::endl;
                    continue;
                }
                std::cerr << "Unknown command: " << line << "\n";
                continue;
            }

            stmt += line + " ";
            size_t last = line.length() - 1;
            while (last > 0 && (line[last] == ' ' || line[last] == '\t')) last--;
            if (line[last] == ';') {
                auto qr = client.query(stmt);
                if (qr.success) {
                    print_remote_result(qr);
                } else {
                    std::cerr << "Error: " << qr.error << "\n";
                }
                stmt.clear();
            }
        }
    }

    return result;
}

//=============================================================================
// Local Mode - Requires DIA SDK (COM)
//=============================================================================

#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include <xsql/socket/server.hpp>
#include <sqlite3.h>

static TablePrinter* g_printer = nullptr;

static int table_callback(void*, int argc, char** argv, char** colNames) {
    if (g_printer) {
        g_printer->add_row(argc, argv, colNames);
    }
    return 0;
}

void print_usage(const char* prog) {
    printf("pdbsql - SQL interface to PDB files\n\n");
    printf("Usage:\n");
    printf("  %s <pdb_file>                       Dump symbol counts\n", prog);
    printf("  %s <pdb_file> \"<query>\"             Execute SQL query (local)\n", prog);
    printf("  %s <pdb_file> -q \"<query>\"          Execute SQL query (local)\n", prog);
    printf("  %s <pdb_file> -i                    Interactive mode (local)\n", prog);
    printf("  %s <pdb_file> --server [port]       Start server (default: 13337)\n", prog);
    printf("  %s --remote host:port -q \"<query>\"  Execute SQL query (remote)\n", prog);
    printf("  %s --remote host:port -i            Interactive mode (remote)\n", prog);
    printf("  %s --token <token>                  Auth token for server/remote mode\n", prog);
    printf("\nTables:\n");
    printf("  functions, publics, data, udts, enums, typedefs, thunks, labels\n");
    printf("  compilands, source_files, line_numbers, sections\n");
    printf("  udt_members, enum_values, base_classes, locals, parameters\n");
    printf("\nExamples:\n");
    printf("  %s test.pdb \"SELECT name, rva FROM functions LIMIT 10\"\n", prog);
    printf("  %s test.pdb \"SELECT * FROM udts WHERE name LIKE '%%Counter%%'\"\n", prog);
    printf("  %s test.pdb --server 13337\n", prog);
    printf("  %s --remote localhost:13337 -q \"SELECT * FROM functions\"\n", prog);
}

bool execute_query(sqlite3* db, const char* sql) {
    char* err = nullptr;
    TablePrinter printer;
    g_printer = &printer;

    int rc = sqlite3_exec(db, sql, table_callback, nullptr, &err);
    g_printer = nullptr;

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err ? err : "unknown");
        if (err) sqlite3_free(err);
        return false;
    }

    printer.print();
    return true;
}

void interactive_mode(sqlite3* db) {
    printf("PDBSQL Interactive Mode. Type .quit to exit.\n\n");

    std::string line;
    std::string stmt;
    while (true) {
        printf(stmt.empty() ? "pdbsql> " : "   ...> ");
        std::getline(std::cin, line);

        if (line.empty()) continue;
        if (line == ".quit" || line == ".exit" || line == "quit" || line == "exit") break;

        if (stmt.empty() && line[0] == '.') {
            if (line == ".tables") {
                execute_query(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
                continue;
            }
            if (line == ".schema") {
                execute_query(db, "SELECT sql FROM sqlite_master WHERE type='table'");
                continue;
            }
            if (line == ".help") {
                printf("Commands: .tables, .schema, .quit, .help\n");
                printf("SQL queries end with semicolon (;)\n");
                continue;
            }
            printf("Unknown command: %s\n", line.c_str());
            continue;
        }

        stmt += line + " ";
        size_t last = line.length() - 1;
        while (last > 0 && (line[last] == ' ' || line[last] == '\t')) last--;
        if (line[last] == ';') {
            execute_query(db, stmt.c_str());
            stmt.clear();
        }
    }
}

void dump_symbol_counts(pdbsql::PdbSession& session) {
    printf("Symbol Counts:\n");
    printf("  Functions:      %ld\n", session.count_symbols(SymTagFunction));
    printf("  Public Symbols: %ld\n", session.count_symbols(SymTagPublicSymbol));
    printf("  Data:           %ld\n", session.count_symbols(SymTagData));
    printf("  UDTs:           %ld\n", session.count_symbols(SymTagUDT));
    printf("  Enums:          %ld\n", session.count_symbols(SymTagEnum));
    printf("  Typedefs:       %ld\n", session.count_symbols(SymTagTypedef));
    printf("  Compilands:     %ld\n", session.count_symbols(SymTagCompiland));
}

//=============================================================================
// Server Mode
//=============================================================================

int run_server_mode(const std::string& pdb_path, int port, const std::string& auth_token) {
    // Open PDB
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("PDBSQL Server - Loaded: %s\n", pdb_path.c_str());

    // Open SQLite in-memory database
    sqlite3* db = nullptr;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to open SQLite database\n");
        return 1;
    }

    // Register virtual tables
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    // Create server
    xsql::socket::Server server;
    if (!auth_token.empty()) {
        xsql::socket::ServerConfig cfg;
        cfg.auth_token = auth_token;
        server.set_config(cfg);
    }
    server.set_query_handler([db](const std::string& sql) -> xsql::socket::QueryResult {
        xsql::socket::QueryResult result;

        // Collect results
        struct Context {
            xsql::socket::QueryResult* result;
            bool first_row;
        } ctx = { &result, true };

        char* err = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(),
            [](void* data, int argc, char** argv, char** colNames) -> int {
                auto* ctx = static_cast<Context*>(data);
                if (ctx->first_row) {
                    for (int i = 0; i < argc; i++) {
                        ctx->result->columns.push_back(colNames[i] ? colNames[i] : "");
                    }
                    ctx->first_row = false;
                }
                std::vector<std::string> row;
                for (int i = 0; i < argc; i++) {
                    row.push_back(argv[i] ? argv[i] : "");
                }
                ctx->result->rows.push_back(std::move(row));
                return 0;
            },
            &ctx, &err);

        if (rc != SQLITE_OK) {
            result.success = false;
            result.error = err ? err : "SQL error";
            if (err) sqlite3_free(err);
        } else {
            result.success = true;
        }

        return result;
    });

    // Run server (blocking)
    printf("Starting server on port %d...\n", port);
    printf("Connect with: pdbsql --remote localhost:%d -q \"SELECT * FROM functions\"\n", port);
    printf("Press Ctrl+C to stop.\n\n");

    server.run(port);

    sqlite3_close(db);
    return 0;
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[]) {
    std::string pdb_path;
    std::string query;
    std::string remote_spec;
    std::string auth_token;
    bool interactive = false;
    bool server_mode = false;
    int server_port = 13337;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            interactive = true;
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            query = argv[++i];
        } else if (strcmp(argv[i], "--server") == 0) {
            server_mode = true;
            // Optional port argument
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                server_port = std::atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--remote") == 0 && i + 1 < argc) {
            remote_spec = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            auth_token = argv[++i];
        } else if (pdb_path.empty() && argv[i][0] != '-') {
            pdb_path = argv[i];
        } else if (query.empty() && argv[i][0] != '-') {
            // Positional query argument (for backwards compatibility)
            query = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    //=========================================================================
    // Remote mode - thin client, no DIA/COM loaded
    //=========================================================================
    if (!remote_spec.empty()) {
        if (!pdb_path.empty()) {
            fprintf(stderr, "Error: Cannot use both PDB path and --remote\n");
            return 1;
        }
        if (server_mode) {
            fprintf(stderr, "Error: Cannot use both --server and --remote\n");
            return 1;
        }

        // Parse host:port
        std::string host = "127.0.0.1";
        int port = 13337;
        auto colon = remote_spec.find(':');
        if (colon != std::string::npos) {
            host = remote_spec.substr(0, colon);
            port = std::stoi(remote_spec.substr(colon + 1));
        } else {
            host = remote_spec;
        }

        return run_remote_mode(host, port, query, auth_token, interactive);
    }

    //=========================================================================
    // Local modes - require PDB path
    //=========================================================================
    if (pdb_path.empty()) {
        fprintf(stderr, "Error: PDB path required (or use --remote)\n\n");
        print_usage(argv[0]);
        return 1;
    }

    //=========================================================================
    // Server mode
    //=========================================================================
    if (server_mode) {
        return run_server_mode(pdb_path, server_port, auth_token);
    }

    //=========================================================================
    // Local query/interactive mode
    //=========================================================================

    // Open PDB
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("pdbsql - Loaded: %s\n\n", pdb_path.c_str());

    // Open SQLite in-memory database
    sqlite3* db = nullptr;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to open SQLite database\n");
        return 1;
    }

    // Register virtual tables
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    // Determine mode
    if (!query.empty()) {
        // Execute query from command line
        execute_query(db, query.c_str());
    } else if (interactive) {
        // Interactive mode
        interactive_mode(db);
    } else {
        // No query - dump counts
        dump_symbol_counts(session);
    }

    sqlite3_close(db);
    return 0;
}
