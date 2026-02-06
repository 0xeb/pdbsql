#include "mcp_mode.hpp"

#ifdef PDBSQL_HAS_AI_AGENT

#include "query_json.hpp"
#include "table_printer.hpp"
#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include "../common/ai_agent.hpp"
#include "../common/mcp_server.hpp"

#include <xsql/database.hpp>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <sstream>
#include <string>

// Forward declaration for query_to_string used by AI agent
static std::string execute_query_to_string(xsql::Database& db, const std::string& sql);

static std::atomic<bool> g_mcp_quit{false};

static void mcp_signal_handler(int) {
    g_mcp_quit.store(true);
}

static TablePrinter* g_mcp_printer = nullptr;

static int mcp_table_callback(void*, int argc, char** argv, char** colNames) {
    if (g_mcp_printer) {
        g_mcp_printer->add_row(argc, argv, colNames);
    }
    return 0;
}

static std::string execute_query_to_string(xsql::Database& db, const std::string& sql) {
    TablePrinter printer;
    g_mcp_printer = &printer;

    int rc = db.exec(sql.c_str(), mcp_table_callback, nullptr);
    g_mcp_printer = nullptr;

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

int run_mcp_mode(const std::string& pdb_path, int port,
                 const std::string& provider_override, bool verbose) {
    // Open PDB
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("PDBSQL MCP Server - Loaded: %s\n", pdb_path.c_str());

    // Create database and register tables
    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    // SQL executor (returns JSON for MCP)
    pdbsql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
        return query_result_to_json(db, sql);
    };

    // Create AI agent for natural language queries
    auto executor = [&db](const std::string& sql) -> std::string {
        return execute_query_to_string(db, sql);
    };
    pdbsql::AgentSettings settings = pdbsql::LoadAgentSettings();
    if (!provider_override.empty()) {
        try {
            settings.default_provider = pdbsql::ParseProviderType(provider_override);
        } catch (...) {}
    }
    pdbsql::AIAgent agent(executor, settings, verbose);
    agent.start();

    pdbsql::AskCallback ask_cb = [&agent](const std::string& question) -> std::string {
        return agent.query(question);
    };

    // Start MCP server
    pdbsql::PdbsqlMCPServer mcp_server;
    int actual_port = mcp_server.start(port, sql_cb, ask_cb, "127.0.0.1", true);
    if (actual_port <= 0) {
        fprintf(stderr, "Error: Failed to start MCP server on port %d\n", port);
        return 1;
    }

    printf("%s", pdbsql::format_mcp_info(actual_port, true).c_str());
    printf("Press Ctrl+C to stop.\n\n");
    fflush(stdout);

    // Set up signal handling
    g_mcp_quit.store(false);
    auto old_handler = std::signal(SIGINT, mcp_signal_handler);
#ifdef _WIN32
    auto old_break_handler = std::signal(SIGBREAK, mcp_signal_handler);
#endif

    mcp_server.set_interrupt_check([]() {
        return g_mcp_quit.load();
    });

    mcp_server.run_until_stopped();

    std::signal(SIGINT, old_handler);
#ifdef _WIN32
    std::signal(SIGBREAK, old_break_handler);
#endif
    printf("\nMCP server stopped.\n");
    return 0;
}

#endif // PDBSQL_HAS_AI_AGENT
