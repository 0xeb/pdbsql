// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/**
 * pdbsql CLI - SQL interface to PDB files
 *
 * Usage:
 *   pdbsql <pdb_file>                      Dump symbol counts
 *   pdbsql <pdb_file> "<query>"            Execute SQL query (local)
 *   pdbsql <pdb_file> -q "<query>"         Execute SQL query (local)
 *   pdbsql <pdb_file> -i                   Interactive mode (local)
 *   pdbsql <pdb_file> --http [port]        Start HTTP server mode
 *   pdbsql <pdb_file> --mcp [port]         Start MCP server mode
 */

#include "table_printer.hpp"
#include "query_json.hpp"
#ifdef PDBSQL_HAS_HTTP
#include "http_mode.hpp"
#endif
#ifdef PDBSQL_HAS_MCP
#include "mcp_mode.hpp"
#endif

#include "pdb_session.hpp"
#include "pdb_tables.hpp"

#include <xsql/database.hpp>

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

static bool parse_port(const std::string &s, int &port) {
    try { port = std::stoi(s); return port > 0 && port <= 65535; }
    catch (...) { return false; }
}

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

//=============================================================================
// Usage
//=============================================================================

static const char* g_copyright = "Copyright (c) 2024-2026 Elias Bachaalany";

static void print_usage(const char* prog) {
    printf("pdbsql - SQL interface to PDB files\n");
    printf("%s\n\n", g_copyright);
    printf("Usage:\n");
    printf("  %s <pdb_file>                       Dump symbol counts\n", prog);
    printf("  %s -s <pdb_file> \"<query>\"          Execute SQL query (local)\n", prog);
    printf("  %s <pdb_file> -q \"<query>\"          Execute SQL query (local)\n", prog);
    printf("  %s <pdb_file> -i                    Interactive mode (local)\n", prog);
    printf("\nOptions:\n");
    printf("  -s, --source <path>    PDB file path (alternative to positional)\n");
    printf("  -q <query>             SQL query to execute\n");
    printf("  -i, --interactive      Interactive SQL mode\n");
    printf("  %s --token <token>                  Auth token for HTTP mode (MCP endpoint is unauthenticated)\n", prog);
#ifdef PDBSQL_HAS_HTTP
    printf("  %s <pdb_file> --http [port]          Start HTTP REST server (default: 8080)\n", prog);
    printf("  %s <pdb_file> --bind <addr>          Bind address for server (default: 127.0.0.1)\n", prog);
#endif
#ifdef PDBSQL_HAS_MCP
    printf("  %s <pdb_file> --mcp [port]           Start MCP server (default: random 9000-9999)\n", prog);
#endif
    printf("\nTables:\n");
    printf("  functions, publics, data, udts, enums, typedefs, thunks, labels\n");
    printf("  compilands, source_files, line_numbers, sections\n");
    printf("  udt_members, enum_values, base_classes, locals, parameters\n");
    printf("\nExamples:\n");
    printf("  %s test.pdb \"SELECT name, rva FROM functions LIMIT 10\"\n", prog);
    printf("  %s test.pdb \"SELECT * FROM udts WHERE name LIKE '%%Counter%%'\"\n", prog);
    printf("  %s test.pdb --http 8080\n", prog);
#ifdef PDBSQL_HAS_MCP
    printf("  %s test.pdb --mcp\n", prog);
#endif
}

//=============================================================================
// Interactive Mode
//=============================================================================

static void interactive_mode(xsql::Database& db) {
    std::string line;
    std::string stmt;

    printf("PDBSQL Interactive Mode. Type .tables, .schema, .help, .quit\n\n");

    while (true) {
        printf(stmt.empty() ? "pdbsql> " : "   ...> ");
        fflush(stdout);
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        // Handle dot commands
        if (stmt.empty() && line[0] == '.') {
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
        }

        // Standard SQL mode: accumulate query
        stmt += line + " ";
        size_t last = line.length() - 1;
        while (last > 0 && (line[last] == ' ' || line[last] == '\t')) last--;
        if (line[last] == ';') {
            execute_query(db, stmt.c_str());
            stmt.clear();
        }
    }
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
    std::string auth_token;
    std::string bind_addr;
    bool interactive = false;
    bool http_mode = false;
    int http_port = 8080;
    bool mcp_mode = false;
    int mcp_port = 0;  // 0 = random port in 9000-9999

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            interactive = true;
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            query = argv[++i];
#ifdef PDBSQL_HAS_MCP
        } else if (strcmp(argv[i], "--mcp") == 0) {
            mcp_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string port_str = argv[++i];
                if (!parse_port(port_str, mcp_port)) {
                    fprintf(stderr, "Invalid MCP port: %s\n", port_str.c_str());
                    return 1;
                }
            }
#endif
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
    // Local modes - require PDB path
    //=========================================================================
    if (pdb_path.empty()) {
        fprintf(stderr, "Error: PDB path required\n\n");
        print_usage(argv[0]);
        return 1;
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

#ifdef PDBSQL_HAS_MCP
    if (mcp_mode) {
        return run_mcp_mode(pdb_path, mcp_port, bind_addr);
    }
#else
    if (mcp_mode) {
        fprintf(stderr, "Error: MCP mode not available. Rebuild with -DPDBSQL_WITH_MCP=ON\n");
        return 1;
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

    printf("pdbsql - Loaded: %s\n", pdb_path.c_str());
    printf("%s\n\n", g_copyright);

    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    if (!query.empty()) {
        execute_query(db, query.c_str());
    } else if (interactive) {
        interactive_mode(db);
    } else {
        dump_symbol_counts(session);
    }

    return 0;
}
