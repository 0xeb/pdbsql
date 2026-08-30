// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <functional>
#include <string>
#include <sstream>

namespace pdbsql {

/**
 * Command handler result
 */
enum class CommandResult {
    NOT_HANDLED,  // Not a command, process as query
    HANDLED,      // Command executed successfully
    QUIT          // User requested quit
};

/**
 * Command handler callbacks
 *
 * These callbacks allow different environments (CLI, plugin) to extend
 * command behavior. For example, .clear might:
 *   - Core: Reset the AI agent session
 *   - Plugin: Also clear output window
 */
struct CommandCallbacks {
    std::function<std::string()> get_tables;      // Return table list
    std::function<std::string(const std::string&)> get_schema;  // Return schema for table
    std::function<std::string()> get_info;        // Return database info
    std::function<std::string()> clear_session;   // Clear/reset session (agent, UI, etc.)

    // MCP server callbacks (optional)
    std::function<std::string()> mcp_status;
    std::function<std::string()> mcp_start;
    std::function<std::string()> mcp_stop;

#ifdef PDBSQL_HAS_HTTP
    // HTTP server callbacks (optional)
    std::function<std::string()> http_status;
    std::function<std::string()> http_start;
    std::function<std::string()> http_stop;
#endif
};

/**
 * Handle dot commands (.tables, .schema, .help, .quit, etc.)
 *
 * @param input User input line
 * @param callbacks Callbacks to execute commands
 * @param output Output string (filled if command produces output)
 * @return CommandResult indicating how to proceed
 */
inline CommandResult handle_command(
    const std::string& input,
    const CommandCallbacks& callbacks,
    std::string& output)
{
    if (input.empty() || input[0] != '.') {
        return CommandResult::NOT_HANDLED;
    }

    if (input == ".quit" || input == ".exit") {
        return CommandResult::QUIT;
    }

    if (input == ".tables") {
        if (callbacks.get_tables) {
            output = callbacks.get_tables();
        }
        return CommandResult::HANDLED;
    }

    if (input == ".info") {
        if (callbacks.get_info) {
            output = callbacks.get_info();
        }
        return CommandResult::HANDLED;
    }

    if (input == ".clear") {
        if (callbacks.clear_session) {
            output = callbacks.clear_session();
        } else {
            output = "Session cleared";
        }
        return CommandResult::HANDLED;
    }

    if (input == ".help") {
        output = "PDBSQL Commands:\n"
                 "  .tables         List all tables\n"
                 "  .schema <table> Show table schema\n"
                 "  .info           Show database info\n"
                 "  .clear          Clear/reset session\n"
                 "  .quit / .exit   Exit\n"
                 "  .help           Show this help\n"

#ifdef PDBSQL_HAS_MCP
                 "\n"
                 "MCP Server:\n"
                 "  .mcp            Show status or start if not running\n"
                 "  .mcp start      Start MCP server\n"
                 "  .mcp stop       Stop MCP server\n"
                 "  .mcp help       Show MCP help\n"
#endif
#ifdef PDBSQL_HAS_HTTP
                 "\n"
                 "HTTP Server:\n"
                 "  .http           Show status or start if not running\n"
                 "  .http start     Start HTTP server\n"
                 "  .http stop      Stop HTTP server\n"
                 "  .http help      Show HTTP help\n"
#endif
                 "\n"
                 "SQL:\n"
                 "  SELECT * FROM functions LIMIT 10;\n"
                 "  SELECT name, rva FROM functions ORDER BY length DESC;\n"
                 ;
        return CommandResult::HANDLED;
    }

    // .mcp commands (MCP server control)
    if (input.rfind(".mcp", 0) == 0) {
#ifdef PDBSQL_HAS_MCP
        std::string subargs = input.length() > 4 ? input.substr(4) : "";
        // Trim leading whitespace
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos)
            subargs = subargs.substr(start);

        if (subargs.empty()) {
            // .mcp - show status, start if not running
            if (callbacks.mcp_status) {
                output = callbacks.mcp_status();
            } else {
                output = "MCP server not available";
            }
        }
        else if (subargs == "start") {
            if (callbacks.mcp_start) {
                output = callbacks.mcp_start();
            } else {
                output = "MCP server not available";
            }
        }
        else if (subargs == "stop") {
            if (callbacks.mcp_stop) {
                output = callbacks.mcp_stop();
            } else {
                output = "MCP server not available";
            }
        }
        else if (subargs == "help") {
            output = "MCP Server Commands:\n"
                     "  .mcp            Show status, start if not running\n"
                     "  .mcp start      Start MCP server on random port\n"
                     "  .mcp stop       Stop MCP server\n"
                     "  .mcp help       Show this help\n"
                     "\n"
                     "The MCP server exposes two tools:\n"
                     "  pdbsql_query  - Execute SQL query directly\n"
                     "  pdbsql_help   - Full reference: schema, patterns, performance traps\n"
                     "\n"
                     "Connect with Claude Desktop by adding to config:\n"
                     "  {\"mcpServers\": {\"pdbsql\": {\"url\": \"http://127.0.0.1:<port>/sse\"}}}\n";
        }
        else {
            output = "Unknown MCP command: " + subargs + "\nUse '.mcp help' for available commands.";
        }
#else
        output = "MCP server not compiled in. Rebuild with -DPDBSQL_WITH_MCP=ON";
#endif
        return CommandResult::HANDLED;
    }

    // .http commands (HTTP server control)
    if (input.rfind(".http", 0) == 0) {
#ifdef PDBSQL_HAS_HTTP
        std::string subargs = input.length() > 5 ? input.substr(5) : "";
        // Trim leading whitespace
        size_t start = subargs.find_first_not_of(" \t");
        if (start != std::string::npos)
            subargs = subargs.substr(start);

        if (subargs.empty()) {
            // .http - show status, start if not running
            if (callbacks.http_status) {
                output = callbacks.http_status();
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "start") {
            if (callbacks.http_start) {
                output = callbacks.http_start();
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "stop") {
            if (callbacks.http_stop) {
                output = callbacks.http_stop();
            } else {
                output = "HTTP server not available";
            }
        }
        else if (subargs == "help") {
            output = "HTTP Server Commands:\n"
                     "  .http            Show status, start if not running\n"
                     "  .http start      Start HTTP server on random port\n"
                     "  .http stop       Stop HTTP server\n"
                     "  .http help       Show this help\n"
                     "\n"
                     "Endpoints:\n"
                     "  GET  /help       API documentation\n"
                     "  POST /query      Execute SQL (body = raw SQL)\n"
                     "  GET  /status     Health check\n"
                     "  POST /shutdown   Stop server\n"
                     "\n"
                     "Example:\n"
                     "  curl -X POST http://127.0.0.1:<port>/query -d \"SELECT name FROM functions LIMIT 5\"\n";
        }
        else {
            output = "Unknown HTTP command: " + subargs + "\nUse '.http help' for available commands.";
        }
#else
        output = "HTTP server not compiled in. Rebuild with -DPDBSQL_WITH_HTTP=ON";
#endif
        return CommandResult::HANDLED;
    }

    if (input.rfind(".schema", 0) == 0) {
        std::string table = input.length() > 8 ? input.substr(8) : "";
        // Trim leading whitespace
        size_t start = table.find_first_not_of(" \t");
        if (start != std::string::npos) {
            table = table.substr(start);
            // Trim trailing whitespace
            size_t end = table.find_last_not_of(" \t");
            if (end != std::string::npos) {
                table = table.substr(0, end + 1);
            }
        } else {
            table.clear();
        }

        if (table.empty()) {
            output = "Usage: .schema <table_name>";
        } else if (callbacks.get_schema) {
            output = callbacks.get_schema(table);
        }
        return CommandResult::HANDLED;
    }

    output = "Unknown command: " + input;
    return CommandResult::HANDLED;
}

} // namespace pdbsql
