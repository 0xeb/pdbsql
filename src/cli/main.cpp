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
 */

#include "table_printer.hpp"
#include "query_json.hpp"
#include "remote_mode.hpp"
#ifdef PDBSQL_HAS_HTTP
#include "http_mode.hpp"
#endif
#ifdef PDBSQL_HAS_AI_AGENT
#include "mcp_mode.hpp"
#endif

#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include "server_query_dispatcher.hpp"

#include <xsql/database.hpp>
#include <xsql/socket/server.hpp>

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
#include <memory>

#ifdef PDBSQL_HAS_AI_AGENT
#include "../common/ai_agent.hpp"
#include "../common/pdbsql_commands.hpp"
#include "../common/mcp_server.hpp"
#ifdef PDBSQL_HAS_HTTP
#include "../common/http_server.hpp"
#endif

namespace {
    std::atomic<bool> g_quit_requested{false};
    pdbsql::AIAgent* g_agent = nullptr;
    std::unique_ptr<pdbsql::PdbsqlMCPServer> g_mcp_server;
    std::unique_ptr<pdbsql::AIAgent> g_mcp_agent;
#ifdef PDBSQL_HAS_HTTP
    std::unique_ptr<pdbsql::PdbsqlHTTPServer> g_repl_http_server;
#endif
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
// Local helpers
//=============================================================================

static TablePrinter* g_printer = nullptr;

static int table_callback(void*, int argc, char** argv, char** colNames) {
    if (g_printer) {
        g_printer->add_row(argc, argv, colNames);
    }
    return 0;
}

static bool execute_query(xsql::Database& db, const char* sql) {
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
static std::string execute_query_to_string(xsql::Database& db, const std::string& sql) {
    TablePrinter printer;
    g_printer = &printer;

    int rc = db.exec(sql.c_str(), table_callback, nullptr);
    g_printer = nullptr;

    if (rc != SQLITE_OK) {
        return "Error: " + db.last_error();
    }

    if (printer.columns.empty()) {
        return "OK (no results)";
    }

    std::stringstream ss;
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

//=============================================================================
// Usage
//=============================================================================

static void print_usage(const char* prog) {
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
    printf("  %s <pdb_file> --mcp [port]          Start MCP server (default: random 9000-9999)\n", prog);
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

//=============================================================================
// Interactive Mode
//=============================================================================

#ifdef PDBSQL_HAS_AI_AGENT
static void interactive_mode(xsql::Database& db, bool agent_mode, bool verbose,
                             const std::string& provider_override = "") {
#else
static void interactive_mode(xsql::Database& db) {
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

        pdbsql::AgentSettings settings = pdbsql::LoadAgentSettings();
        if (!provider_override.empty()) {
            try {
                settings.default_provider = pdbsql::ParseProviderType(provider_override);
            } catch (...) {}
        }

        agent = std::make_unique<pdbsql::AIAgent>(executor, settings, verbose);
        g_agent = agent.get();
        std::signal(SIGINT, signal_handler);
#ifdef _WIN32
        std::signal(SIGBREAK, signal_handler);
#endif
        agent->start();

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
        if (stmt.empty() && line[0] == '.') {
#ifdef PDBSQL_HAS_AI_AGENT
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
                return "PDBSQL Database\n";
            };
            callbacks.clear_session = [&agent]() -> std::string {
                if (agent) {
                    agent->reset_session();
                    return "Session cleared (conversation history reset)";
                }
                return "Session cleared";
            };

            // MCP server callbacks
            callbacks.mcp_status = []() -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    return pdbsql::format_mcp_status(g_mcp_server->port(), true);
                }
                return "MCP server not running\nUse '.mcp start' to start\n";
            };
            callbacks.mcp_start = [&db]() -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    return pdbsql::format_mcp_status(g_mcp_server->port(), true);
                }
                if (!g_mcp_server) {
                    g_mcp_server = std::make_unique<pdbsql::PdbsqlMCPServer>();
                }
                pdbsql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
                    return query_result_to_json(db, sql);
                };
                g_mcp_agent = std::make_unique<pdbsql::AIAgent>(sql_cb);
                g_mcp_agent->start();
                pdbsql::AskCallback ask_cb = [](const std::string& question) -> std::string {
                    if (!g_mcp_agent) return "Error: AI agent not available";
                    return g_mcp_agent->query(question);
                };
                int port = g_mcp_server->start(0, sql_cb, ask_cb, "127.0.0.1", true);
                if (port <= 0) {
                    g_mcp_agent.reset();
                    return "Error: Failed to start MCP server\n";
                }
                printf("%s", pdbsql::format_mcp_info(port, true).c_str());
                printf("Press Ctrl+C to stop MCP server and return to REPL...\n\n");
                fflush(stdout);
                g_quit_requested.store(false);
                auto old_handler = std::signal(SIGINT, signal_handler);
#ifdef _WIN32
                auto old_break_handler = std::signal(SIGBREAK, signal_handler);
#endif
                g_mcp_server->set_interrupt_check([]() { return g_quit_requested.load(); });
                g_mcp_server->run_until_stopped();
                std::signal(SIGINT, old_handler);
#ifdef _WIN32
                std::signal(SIGBREAK, old_break_handler);
#endif
                g_mcp_agent.reset();
                g_quit_requested.store(false);
                return "MCP server stopped. Returning to REPL.\n";
            };
            callbacks.mcp_stop = []() -> std::string {
                if (g_mcp_server && g_mcp_server->is_running()) {
                    g_mcp_server->stop();
                    g_mcp_agent.reset();
                    return "MCP server stopped\n";
                }
                return "MCP server not running\n";
            };

#ifdef PDBSQL_HAS_HTTP
            callbacks.http_status = []() -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    return pdbsql::format_http_status(g_repl_http_server->port(), true);
                }
                return "HTTP server not running\nUse '.http start' to start\n";
            };
            callbacks.http_start = [&db]() -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    return pdbsql::format_http_status(g_repl_http_server->port(), true);
                }
                if (!g_repl_http_server) {
                    g_repl_http_server = std::make_unique<pdbsql::PdbsqlHTTPServer>();
                }
                pdbsql::HTTPQueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
                    return query_result_to_json(db, sql);
                };
                int port = g_repl_http_server->start(0, sql_cb, "127.0.0.1", true);
                if (port <= 0) {
                    return "Error: Failed to start HTTP server\n";
                }
                printf("%s", pdbsql::format_http_info(port).c_str());
                fflush(stdout);
                g_quit_requested.store(false);
                auto old_handler = std::signal(SIGINT, signal_handler);
#ifdef _WIN32
                auto old_break_handler = std::signal(SIGBREAK, signal_handler);
#endif
                g_repl_http_server->set_interrupt_check([]() { return g_quit_requested.load(); });
                g_repl_http_server->run_until_stopped();
                std::signal(SIGINT, old_handler);
#ifdef _WIN32
                std::signal(SIGBREAK, old_break_handler);
#endif
                g_quit_requested.store(false);
                return "HTTP server stopped. Returning to REPL.\n";
            };
            callbacks.http_stop = []() -> std::string {
                if (g_repl_http_server && g_repl_http_server->is_running()) {
                    g_repl_http_server->stop();
                    return "HTTP server stopped\n";
                }
                return "HTTP server not running\n";
            };
#endif // PDBSQL_HAS_HTTP

            std::string output;
            auto result = pdbsql::handle_command(line, callbacks, output);
            switch (result) {
                case pdbsql::CommandResult::QUIT:
                    goto exit_interactive;
                case pdbsql::CommandResult::HANDLED:
                    if (!output.empty()) {
                        printf("%s", output.c_str());
                        if (output.back() != '\n') printf("\n");
                    }
                    continue;
                case pdbsql::CommandResult::NOT_HANDLED:
                    break;
            }
#else
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
        if (agent_mode && agent) {
            std::string result = agent->query(line);
            if (!result.empty()) {
                printf("%s\n", result.c_str());
            }
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
    if (g_mcp_server) { g_mcp_server->stop(); g_mcp_server.reset(); }
    g_mcp_agent.reset();
#ifdef PDBSQL_HAS_HTTP
    if (g_repl_http_server) { g_repl_http_server->stop(); g_repl_http_server.reset(); }
#endif
    if (agent) { agent->stop(); g_agent = nullptr; }
    std::signal(SIGINT, SIG_DFL);
#endif
}

//=============================================================================
// Server Mode
//=============================================================================

static int run_server_mode(const std::string& pdb_path, int port, const std::string& auth_token) {
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("PDBSQL Server - Loaded: %s\n", pdb_path.c_str());

    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

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

    printf("Starting server on port %d...\n", port);
    printf("Connect with: pdbsql --remote localhost:%d -q \"SELECT * FROM functions\"\n", port);
    printf("Press Ctrl+C to stop.\n\n");

    server.run(port);
    return 0;
}

static void dump_symbol_counts(pdbsql::PdbSession& session) {
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
    std::string nl_prompt;
    bool agent_mode = false;
    bool verbose_mode = false;
    std::string provider_override;
    bool mcp_mode = false;
    int mcp_port = 0;
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
            if (provider_override != "copilot" && provider_override != "Copilot" &&
                provider_override != "claude" && provider_override != "Claude") {
                fprintf(stderr, "Invalid provider: %s (use 'claude' or 'copilot')\n", provider_override.c_str());
                return 1;
            }
        } else if (strcmp(argv[i], "--mcp") == 0) {
            mcp_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string port_str = argv[++i];
                if (!parse_port(port_str, mcp_port)) {
                    fprintf(stderr, "Invalid MCP port: %s\n", port_str.c_str());
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "--config") == 0) {
            std::string config_path = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            std::string config_value = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
            auto [ok, output, code] = pdbsql::handle_config_command(config_path, config_value);
            printf("%s", output.c_str());
            return code;
#endif
        } else if (strcmp(argv[i], "--server") == 0) {
            server_mode = true;
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
            query = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    //=========================================================================
    // Remote mode
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

    if (server_mode) {
        return run_server_mode(pdb_path, server_port, auth_token);
    }

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

#ifdef PDBSQL_HAS_AI_AGENT
    if (mcp_mode) {
        return run_mcp_mode(pdb_path, mcp_port, provider_override, verbose_mode);
    }
#endif

    //=========================================================================
    // Local query/interactive mode
    //=========================================================================

    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("pdbsql - Loaded: %s\n\n", pdb_path.c_str());

    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    if (!query.empty()) {
        execute_query(db, query.c_str());
#ifdef PDBSQL_HAS_AI_AGENT
    } else if (!nl_prompt.empty()) {
        auto executor = [&db](const std::string& sql) -> std::string {
            return execute_query_to_string(db, sql);
        };

        pdbsql::AgentSettings settings = pdbsql::LoadAgentSettings();
        if (!provider_override.empty()) {
            try {
                settings.default_provider = pdbsql::ParseProviderType(provider_override);
            } catch (...) {}
        }

        pdbsql::AIAgent agent(executor, settings, verbose_mode);
        g_agent = &agent;
        std::signal(SIGINT, signal_handler);
#ifdef _WIN32
        std::signal(SIGBREAK, signal_handler);
#endif
        agent.start();

        std::string result = agent.query(nl_prompt);
        if (!result.empty()) {
            printf("%s\n", result.c_str());
        }

        agent.stop();
        g_agent = nullptr;
        std::signal(SIGINT, SIG_DFL);
#endif
    } else if (interactive) {
#ifdef PDBSQL_HAS_AI_AGENT
        interactive_mode(db, agent_mode, verbose_mode, provider_override);
#else
        interactive_mode(db);
#endif
    } else {
        dump_symbol_counts(session);
    }

    return 0;
}
