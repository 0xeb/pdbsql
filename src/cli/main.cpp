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
#include <csignal>
#include <atomic>
#include <sstream>
#include <mutex>
#include <thread>
#include <chrono>

// Socket client for remote mode (no DIA dependency)
#include <xsql/socket/client.hpp>
#ifdef PDBSQL_HAS_HTTP
#include <xsql/thinclient/server.hpp>
#endif

// AI Agent integration (optional, enabled via PDBSQL_WITH_AI_AGENT)
#ifdef PDBSQL_HAS_AI_AGENT
#include "../common/ai_agent.hpp"
#include "../common/pdbsql_commands.hpp"

// Global signal handler state
namespace {
    std::atomic<bool> g_quit_requested{false};
    pdbsql::AIAgent* g_agent = nullptr;
}

extern "C" void signal_handler(int sig) {
    (void)sig;
    g_quit_requested.store(true);
    if (g_agent) {
        g_agent->request_quit();
    }
}
#endif

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

static bool parse_port(const std::string& s, int& port) {
    try {
        size_t idx = 0;
        int v = std::stoi(s, &idx, 10);
        if (idx != s.size()) return false;
        if (v < 1 || v > 65535) return false;
        port = v;
        return true;
    } catch (...) {
        return false;
    }
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
#include "server_query_dispatcher.hpp"
#include <xsql/database.hpp>
#include <xsql/socket/server.hpp>

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
    printf("  %s -s <pdb_file> \"<query>\"          Execute SQL query (local)\n", prog);
    printf("  %s <pdb_file> -q \"<query>\"          Execute SQL query (local)\n", prog);
    printf("  %s <pdb_file> -i                    Interactive mode (local)\n", prog);
    printf("  %s <pdb_file> --server [port]       Start server (default: 13337)\n", prog);
    printf("\nOptions:\n");
    printf("  -s, --source <path>    PDB file path (alternative to positional)\n");
    printf("  -q <query>             SQL query to execute\n");
    printf("  -i, --interactive      Interactive SQL mode\n");
    printf("  %s --remote host:port -q \"<query>\"  Execute SQL query (remote)\n", prog);
    printf("  %s --remote host:port -i            Interactive mode (remote)\n", prog);
    printf("  %s --token <token>                  Auth token for server/remote mode\n", prog);
#ifdef PDBSQL_HAS_HTTP
    printf("  %s <pdb_file> --http [port]          Start HTTP REST server (default: 8080)\n", prog);
    printf("  %s <pdb_file> --bind <addr>          Bind address for HTTP (default: 127.0.0.1)\n", prog);
#endif
#ifdef PDBSQL_HAS_AI_AGENT
    printf("  %s <pdb_file> --prompt \"<text>\"     Natural language query (AI agent)\n", prog);
    printf("  %s <pdb_file> -i --agent            Interactive mode with AI agent\n", prog);
    printf("  %s <pdb_file> --provider <name>     Override AI provider (claude, copilot)\n", prog);
    printf("  %s --config [path] [value]          View/set agent configuration\n", prog);
    printf("  %s <pdb_file> -v                    Show agent debug logs\n", prog);
#endif
    printf("\nTables:\n");
    printf("  functions, publics, data, udts, enums, typedefs, thunks, labels\n");
    printf("  compilands, source_files, line_numbers, sections\n");
    printf("  udt_members, enum_values, base_classes, locals, parameters\n");
#ifdef PDBSQL_HAS_AI_AGENT
    printf("\nAgent settings stored in: ~/.pdbsql/agent_settings.json (or %%APPDATA%%\\pdbsql on Windows)\n");
#endif
    printf("\nExamples:\n");
    printf("  %s test.pdb \"SELECT name, rva FROM functions LIMIT 10\"\n", prog);
    printf("  %s test.pdb \"SELECT * FROM udts WHERE name LIKE '%%Counter%%'\"\n", prog);
    printf("  %s test.pdb --server 13337\n", prog);
    printf("  %s --remote localhost:13337 -q \"SELECT * FROM functions\"\n", prog);
#ifdef PDBSQL_HAS_AI_AGENT
    printf("  %s test.pdb --prompt \"Find the largest functions\"\n", prog);
    printf("  %s test.pdb -i --agent\n", prog);
#endif
}

bool execute_query(xsql::Database& db, const char* sql) {
    TablePrinter printer;
    g_printer = &printer;

    int rc = db.exec(sql, table_callback, nullptr);
    g_printer = nullptr;

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", db.last_error().c_str());
        return false;
    }

    printer.print();
    return true;
}

#ifdef PDBSQL_HAS_AI_AGENT
// Execute SQL and return formatted results as string (for AI agent)
std::string execute_query_to_string(xsql::Database& db, const std::string& sql) {
    TablePrinter printer;
    g_printer = &printer;

    int rc = db.exec(sql.c_str(), table_callback, nullptr);
    g_printer = nullptr;

    if (rc != SQLITE_OK) {
        return "Error: " + db.last_error();
    }

    // Format as table string
    if (printer.columns.empty()) {
        return "OK (no results)";
    }

    std::stringstream ss;

    // Header separator
    std::string sep = "+";
    for (size_t w : printer.widths) {
        sep += std::string(w + 2, '-') + "+";
    }

    ss << sep << "\n| ";
    for (size_t i = 0; i < printer.columns.size(); i++) {
        ss << std::left;
        ss.width(printer.widths[i]);
        ss << printer.columns[i] << " | ";
    }
    ss << "\n" << sep << "\n";

    // Rows
    for (const auto& row : printer.rows) {
        ss << "| ";
        for (size_t i = 0; i < row.size(); i++) {
            ss << std::left;
            ss.width(printer.widths[i]);
            ss << row[i] << " | ";
        }
        ss << "\n";
    }
    ss << sep << "\n";
    ss << printer.rows.size() << " row(s)\n";

    return ss.str();
}
#endif

#ifdef PDBSQL_HAS_AI_AGENT
void interactive_mode(xsql::Database& db, bool agent_mode, bool verbose,
                      const std::string& provider_override = "") {
#else
void interactive_mode(xsql::Database& db) {
    [[maybe_unused]] bool agent_mode = false;
#endif
    std::string line;
    std::string stmt;

#ifdef PDBSQL_HAS_AI_AGENT
    std::unique_ptr<pdbsql::AIAgent> agent;
    if (agent_mode) {
        auto executor = [&db](const std::string& sql) -> std::string {
            return execute_query_to_string(db, sql);
        };

        // Load settings (includes BYOK, provider, timeout)
        pdbsql::AgentSettings settings = pdbsql::LoadAgentSettings();

        // Apply provider override from CLI if specified
        if (!provider_override.empty()) {
            try {
                settings.default_provider = pdbsql::ParseProviderType(provider_override);
            } catch (...) {
                // Already validated in argument parsing
            }
        }

        agent = std::make_unique<pdbsql::AIAgent>(executor, settings, verbose);

        // Register signal handler for clean Ctrl-C handling
        g_agent = agent.get();
        std::signal(SIGINT, signal_handler);
#ifdef _WIN32
        // Windows also needs SIGBREAK for Ctrl-Break
        std::signal(SIGBREAK, signal_handler);
#endif

        agent->start();  // Initialize agent

        printf("PDBSQL AI Agent Mode\n");
        printf("Ask questions in natural language or use SQL directly.\n");
        printf("Type .help for commands, .clear to reset, .quit to exit\n\n");
    } else {
#endif
        printf("PDBSQL Interactive Mode. Type .help, .clear, .quit\n\n");
#ifdef PDBSQL_HAS_AI_AGENT
    }
#endif

    while (true) {
#ifdef PDBSQL_HAS_AI_AGENT
        // Check for quit request from signal handler
        if (g_quit_requested.load()) {
            printf("\nInterrupted.\n");
            break;
        }
#endif

        printf(stmt.empty() ? "pdbsql> " : "   ...> ");
        fflush(stdout);
        if (!std::getline(std::cin, line)) break;

        if (line.empty()) continue;

        // Handle dot commands
        if (stmt.empty() && !line.empty() && line[0] == '.') {
#ifdef PDBSQL_HAS_AI_AGENT
            // Use unified command handler for agent mode
            pdbsql::CommandCallbacks callbacks;
            callbacks.get_tables = [&db]() -> std::string {
                std::stringstream ss;
                TablePrinter printer;
                g_printer = &printer;
                db.exec("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", table_callback, nullptr);
                g_printer = nullptr;
                for (const auto& row : printer.rows) {
                    if (row.size() > 0) ss << row[0] << "\n";
                }
                return ss.str();
            };
            callbacks.get_schema = [&db](const std::string& table) -> std::string {
                std::string sql = "SELECT sql FROM sqlite_master WHERE name='" + table + "'";
                TablePrinter printer;
                g_printer = &printer;
                db.exec(sql.c_str(), table_callback, nullptr);
                g_printer = nullptr;
                if (!printer.rows.empty() && printer.rows[0].size() > 0) {
                    return printer.rows[0][0];
                }
                return "Table not found: " + table;
            };
            callbacks.get_info = [&db]() -> std::string {
                return "PDBSQL Database\n";  // Could add more info here
            };
            callbacks.clear_session = [&agent]() -> std::string {
                if (agent) {
                    agent->reset_session();
                    return "Session cleared (conversation history reset)";
                }
                return "Session cleared";
            };

            std::string output;
            auto result = pdbsql::handle_command(line, callbacks, output);

            switch (result) {
                case pdbsql::CommandResult::QUIT:
                    goto exit_interactive;  // Exit the while loop
                case pdbsql::CommandResult::HANDLED:
                    if (!output.empty()) {
                        printf("%s", output.c_str());
                        if (output.back() != '\n') printf("\n");
                    }
                    continue;
                case pdbsql::CommandResult::NOT_HANDLED:
                    // Fall through to standard handling
                    break;
            }
#else
            // Non-agent mode: basic command handling
            if (line == ".quit" || line == ".exit" || line == "quit" || line == "exit") break;
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
#endif
        }

#ifdef PDBSQL_HAS_AI_AGENT
        // In agent mode, use AI for natural language or SQL passthrough
        if (agent_mode && agent) {
            std::string result = agent->query(line);
            if (!result.empty()) {
                printf("%s\n", result.c_str());
            }

            // Check if we were interrupted
            if (agent->quit_requested()) {
                printf("Interrupted.\n");
                break;
            }
            continue;
        }
#endif

        // Standard SQL mode: accumulate query
        stmt += line + " ";
        size_t last = line.length() - 1;
        while (last > 0 && (line[last] == ' ' || line[last] == '\t')) last--;
        if (line[last] == ';') {
            execute_query(db, stmt.c_str());
            stmt.clear();
        }
    }

#ifdef PDBSQL_HAS_AI_AGENT
exit_interactive:
    if (agent) {
        agent->stop();
        g_agent = nullptr;
    }
    // Restore default signal handler
    std::signal(SIGINT, SIG_DFL);
#endif
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
    xsql::Database db;

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
    pdbsql::ServerQueryDispatcher dispatcher(db);
    server.set_query_handler([&dispatcher](const std::string& sql) -> xsql::socket::QueryResult {
        return dispatcher.run(sql);
    });

    // Run server (blocking)
    printf("Starting server on port %d...\n", port);
    printf("Connect with: pdbsql --remote localhost:%d -q \"SELECT * FROM functions\"\n", port);
    printf("Press Ctrl+C to stop.\n\n");

    server.run(port);

    return 0;
}

//=============================================================================
// HTTP Server Mode
//=============================================================================

#ifdef PDBSQL_HAS_HTTP
static xsql::thinclient::server* g_http_server = nullptr;

static void http_signal_handler(int) {
    if (g_http_server) g_http_server->stop();
}

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 10);
    for (char ch : s) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(ch));
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
    return out;
}

static std::string query_result_to_json(xsql::Database& db, const std::string& sql) {
    auto result = db.query(sql);
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (result.ok() ? "true" : "false");

    if (result.ok()) {
        json << ",\"columns\":[";
        for (size_t i = 0; i < result.columns.size(); i++) {
            if (i > 0) json << ",";
            json << "\"" << json_escape(result.columns[i]) << "\"";
        }
        json << "]";

        json << ",\"rows\":[";
        for (size_t i = 0; i < result.rows.size(); i++) {
            if (i > 0) json << ",";
            json << "[";
            for (size_t c = 0; c < result.rows[i].size(); c++) {
                if (c > 0) json << ",";
                json << "\"" << json_escape(result.rows[i][c]) << "\"";
            }
            json << "]";
        }
        json << "]";
        json << ",\"row_count\":" << result.rows.size();
    } else {
        json << ",\"error\":\"" << json_escape(result.error) << "\"";
    }

    json << "}";
    return json.str();
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

Example:
  curl http://localhost:8080/help
  curl -X POST http://localhost:8080/query -d "SELECT name FROM functions LIMIT 5"
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

        // GET /health - Alias for /status
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

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[]) {
    std::string pdb_path;
    std::string query;
    std::string remote_spec;
    std::string auth_token;
    std::string bind_addr;
    bool interactive = false;
    bool server_mode = false;
    bool http_mode = false;
    int server_port = 13337;
    int http_port = 8080;
#ifdef PDBSQL_HAS_AI_AGENT
    std::string nl_prompt;            // --prompt for natural language
    bool agent_mode = false;          // --agent for interactive mode
    bool verbose_mode = false;        // -v for verbose agent output
    std::string provider_override;    // --provider overrides stored setting
#endif

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            interactive = true;
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            query = argv[++i];
#ifdef PDBSQL_HAS_AI_AGENT
        } else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
            nl_prompt = argv[++i];
        } else if (strcmp(argv[i], "--agent") == 0) {
            agent_mode = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose_mode = true;
        } else if (strcmp(argv[i], "--provider") == 0 && i + 1 < argc) {
            provider_override = argv[++i];
            // Validate provider name
            if (provider_override != "copilot" && provider_override != "Copilot" &&
                provider_override != "claude" && provider_override != "Claude") {
                fprintf(stderr, "Invalid provider: %s (use 'claude' or 'copilot')\n", provider_override.c_str());
                return 1;
            }
        } else if (strcmp(argv[i], "--config") == 0) {
            // Handle --config [path] [value] and exit immediately
            std::string config_path = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            std::string config_value = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            auto [ok, output, code] = pdbsql::handle_config_command(config_path, config_value);
            printf("%s", output.c_str());
            return code;
#endif
        } else if (strcmp(argv[i], "--server") == 0) {
            server_mode = true;
            // Optional port argument
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string port_str = argv[++i];
                if (!parse_port(port_str, server_port)) {
                    fprintf(stderr, "Invalid port: %s\n", port_str.c_str());
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "--remote") == 0 && i + 1 < argc) {
            remote_spec = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            auth_token = argv[++i];
        } else if (strcmp(argv[i], "--http") == 0) {
            http_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string port_str = argv[++i];
                if (!parse_port(port_str, http_port)) {
                    fprintf(stderr, "Invalid HTTP port: %s\n", port_str.c_str());
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_addr = argv[++i];
        } else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--source") == 0) && i + 1 < argc) {
            pdb_path = argv[++i];
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
        if (server_mode || http_mode) {
            fprintf(stderr, "Error: Cannot use both --server/--http and --remote\n");
            return 1;
        }

        // Parse host:port
        std::string host = "127.0.0.1";
        int port = 13337;
        auto colon = remote_spec.find(':');
        if (colon != std::string::npos) {
            host = remote_spec.substr(0, colon);
            std::string port_str = remote_spec.substr(colon + 1);
            if (!parse_port(port_str, port)) {
                fprintf(stderr, "Invalid port in --remote: %s\n", port_str.c_str());
                return 1;
            }
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
    // HTTP server mode
    //=========================================================================
#ifdef PDBSQL_HAS_HTTP
    if (http_mode) {
        return run_http_mode(pdb_path, http_port, bind_addr, auth_token);
    }
#else
    if (http_mode) {
        fprintf(stderr, "Error: HTTP mode not available. Rebuild with -DPDBSQL_WITH_HTTP=ON\n");
        return 1;
    }
#endif

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
    xsql::Database db;

    // Register virtual tables
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    // Determine mode
    if (!query.empty()) {
        // Execute query from command line
        execute_query(db, query.c_str());
#ifdef PDBSQL_HAS_AI_AGENT
    } else if (!nl_prompt.empty()) {
        // Natural language prompt mode (one-shot)
        auto executor = [&db](const std::string& sql) -> std::string {
            return execute_query_to_string(db, sql);
        };

        // Load settings
        pdbsql::AgentSettings settings = pdbsql::LoadAgentSettings();
        if (!provider_override.empty()) {
            try {
                settings.default_provider = pdbsql::ParseProviderType(provider_override);
            } catch (...) {}
        }

        pdbsql::AIAgent agent(executor, settings, verbose_mode);

        // Register signal handler
        g_agent = &agent;
        std::signal(SIGINT, signal_handler);
#ifdef _WIN32
        std::signal(SIGBREAK, signal_handler);
#endif

        agent.start();

        // Execute query
        std::string result = agent.query(nl_prompt);
        if (!result.empty()) {
            printf("%s\n", result.c_str());
        }

        agent.stop();
        g_agent = nullptr;
        std::signal(SIGINT, SIG_DFL);
#endif
    } else if (interactive) {
        // Interactive mode
#ifdef PDBSQL_HAS_AI_AGENT
        interactive_mode(db, agent_mode, verbose_mode, provider_override);
#else
        interactive_mode(db);
#endif
    } else {
        // No query - dump counts
        dump_symbol_counts(session);
    }

    return 0;
}
