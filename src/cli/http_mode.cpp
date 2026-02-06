#include "http_mode.hpp"

#ifdef PDBSQL_HAS_HTTP

#include "query_json.hpp"
#include "pdb_session.hpp"
#include "pdb_tables.hpp"

#include <xsql/database.hpp>
#include <xsql/thinclient/server.hpp>

#include <csignal>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>

static xsql::thinclient::server* g_http_server = nullptr;

static void http_signal_handler(int) {
    if (g_http_server) g_http_server->stop();
}

static const char* PDBSQL_HELP_TEXT = R"(PDBSQL HTTP REST API
====================

SQL interface for Windows PDB debug symbols via HTTP.

Endpoints:
  GET  /         - Welcome message
  GET  /help     - This documentation (for LLM discovery)
  POST /query    - Execute SQL (body = raw SQL, response = JSON)
  GET  /status   - Server health
  GET  /health   - Alias for /status
  POST /shutdown - Stop server

Tables:
  functions       - Functions with RVA, size, section info
  publics         - Public symbols
  data            - Data symbols (global/static variables)
  udts            - User-defined types (classes, structs, unions)
  enums           - Enumerations
  typedefs        - Type definitions
  thunks          - Thunk symbols
  labels          - Labels
  compilands      - Compilation units
  source_files    - Source file paths
  line_numbers    - Line number mappings
  sections        - PE sections
  udt_members     - UDT member fields
  enum_values     - Enumeration values
  base_classes    - Class inheritance
  locals          - Local variables
  parameters      - Function parameters

Example Queries:
  SELECT name, rva, size FROM functions ORDER BY size DESC LIMIT 10;
  SELECT name FROM udts WHERE kind = 'class';
  SELECT * FROM sections;

Response Format:
  Success: {"success": true, "columns": [...], "rows": [[...]], "row_count": N}
  Error:   {"success": false, "error": "message"}

Authentication (if enabled):
  Header: Authorization: Bearer <token>
  Or:     X-XSQL-Token: <token>

Example:
  curl http://localhost:8081/help
  curl -X POST http://localhost:8081/query -d "SELECT name FROM functions LIMIT 5"
)";

int run_http_mode(const std::string& pdb_path, int port, const std::string& bind_addr, const std::string& auth_token) {
    // Open PDB
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("PDBSQL HTTP Server - Loaded: %s\n", pdb_path.c_str());

    // Create database and register tables
    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    xsql::thinclient::server_config cfg;
    cfg.port = port;
    cfg.bind_address = bind_addr.empty() ? "127.0.0.1" : bind_addr;
    if (!auth_token.empty()) cfg.auth_token = auth_token;
    if (!bind_addr.empty() && bind_addr != "127.0.0.1" && bind_addr != "localhost") {
        cfg.allow_insecure_no_auth = auth_token.empty();
        fprintf(stderr, "WARNING: Binding to non-loopback address %s\n", bind_addr.c_str());
        if (auth_token.empty()) {
            fprintf(stderr, "WARNING: No authentication token set. Server is accessible without authentication.\n");
            fprintf(stderr, "         Consider using --token <secret> for remote access.\n");
        }
    }

    std::mutex query_mutex;

    cfg.setup_routes = [&db, &pdb_path, &auth_token, &query_mutex, port](httplib::Server& svr) {
        svr.Get("/", [port](const httplib::Request&, httplib::Response& res) {
            std::string welcome = "PDBSQL HTTP Server\n\nEndpoints:\n"
                "  GET  /help     - API documentation\n"
                "  POST /query    - Execute SQL query\n"
                "  GET  /status   - Health check\n"
                "  POST /shutdown - Stop server\n\n"
                "Example: curl -X POST http://localhost:" + std::to_string(port) + "/query -d \"SELECT name FROM functions LIMIT 5\"\n";
            res.set_content(welcome, "text/plain");
        });

        svr.Get("/help", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(PDBSQL_HELP_TEXT, "text/plain");
        });

        svr.Post("/query", [&db, &auth_token, &query_mutex](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string token;
                if (req.has_header("X-XSQL-Token")) token = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto auth = req.get_header_value("Authorization");
                    if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
                }
                if (token != auth_token) {
                    res.status = 401;
                    res.set_content("{\"success\":false,\"error\":\"Unauthorized\"}", "application/json");
                    return;
                }
            }
            if (req.body.empty()) {
                res.status = 400;
                res.set_content("{\"success\":false,\"error\":\"Empty query\"}", "application/json");
                return;
            }
            std::lock_guard<std::mutex> lock(query_mutex);
            res.set_content(query_result_to_json(db, req.body), "application/json");
        });

        svr.Get("/status", [&db, &pdb_path, &auth_token](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string token;
                if (req.has_header("X-XSQL-Token")) token = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto auth = req.get_header_value("Authorization");
                    if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
                }
                if (token != auth_token) {
                    res.status = 401;
                    res.set_content("{\"success\":false,\"error\":\"Unauthorized\"}", "application/json");
                    return;
                }
            }
            auto result = db.query("SELECT COUNT(*) FROM functions");
            std::string count = result.ok() && !result.empty() ? result[0][0] : "?";
            res.set_content("{\"success\":true,\"status\":\"ok\",\"tool\":\"pdbsql\",\"pdb\":\"" + json_escape(pdb_path) + "\",\"functions\":" + count + "}", "application/json");
        });

        svr.Get("/health", [&db, &pdb_path, &auth_token](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string token;
                if (req.has_header("X-XSQL-Token")) token = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto auth = req.get_header_value("Authorization");
                    if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
                }
                if (token != auth_token) {
                    res.status = 401;
                    res.set_content("{\"success\":false,\"error\":\"Unauthorized\"}", "application/json");
                    return;
                }
            }
            auto result = db.query("SELECT COUNT(*) FROM functions");
            std::string count = result.ok() && !result.empty() ? result[0][0] : "?";
            res.set_content("{\"success\":true,\"status\":\"ok\",\"tool\":\"pdbsql\",\"pdb\":\"" + json_escape(pdb_path) + "\",\"functions\":" + count + "}", "application/json");
        });

        svr.Post("/shutdown", [&svr, &auth_token](const httplib::Request& req, httplib::Response& res) {
            if (!auth_token.empty()) {
                std::string token;
                if (req.has_header("X-XSQL-Token")) token = req.get_header_value("X-XSQL-Token");
                else if (req.has_header("Authorization")) {
                    auto auth = req.get_header_value("Authorization");
                    if (auth.rfind("Bearer ", 0) == 0) token = auth.substr(7);
                }
                if (token != auth_token) {
                    res.status = 401;
                    res.set_content("{\"success\":false,\"error\":\"Unauthorized\"}", "application/json");
                    return;
                }
            }
            res.set_content("{\"success\":true,\"message\":\"Shutting down\"}", "application/json");
            std::thread([&svr] {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                svr.stop();
            }).detach();
        });
    };

    xsql::thinclient::server http_server(cfg);
    g_http_server = &http_server;

    auto old_handler = std::signal(SIGINT, http_signal_handler);
#ifdef _WIN32
    auto old_break_handler = std::signal(SIGBREAK, http_signal_handler);
#else
    auto old_term_handler = std::signal(SIGTERM, http_signal_handler);
#endif

    printf("HTTP server listening on http://%s:%d\n", cfg.bind_address.c_str(), port);
    printf("Endpoints: /help, /query, /status, /shutdown\n");
    printf("Example: curl http://localhost:%d/help\n", port);
    printf("Press Ctrl+C to stop.\n\n");
    fflush(stdout);

    http_server.run();

    std::signal(SIGINT, old_handler);
#ifdef _WIN32
    std::signal(SIGBREAK, old_break_handler);
#else
    std::signal(SIGTERM, old_term_handler);
#endif
    g_http_server = nullptr;
    printf("\nHTTP server stopped.\n");
    return 0;
}

#endif // PDBSQL_HAS_HTTP
