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

#include "cli_render.hpp"
#include "query_json.hpp"
#ifdef PDBSQL_HAS_HTTP
#include "http_mode.hpp"
#endif
#ifdef PDBSQL_HAS_MCP
#include "mcp_mode.hpp"
#endif

#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include "pdb_runtime_settings.hpp"

#include <xsql/database.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <vector>
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

// Splits a comma-separated `--warm-tables` value into individual table
// names, trimming surrounding whitespace on each so `a, b,c` parses the
// same as `a,b,c`. Empty entries (a stray leading/trailing/doubled comma)
// are dropped rather than surfaced as an invalid table name.
static std::vector<std::string> split_warm_table_names(const std::string& csv) {
    std::vector<std::string> out;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        size_t start = item.find_first_not_of(" \t");
        size_t end = item.find_last_not_of(" \t");
        if (start == std::string::npos) continue;
        out.push_back(item.substr(start, end - start + 1));
    }
    return out;
}

//=============================================================================
// Local helpers
//=============================================================================

// Machine-readable / file output options for the local query path.
struct OutputOptions {
    std::string format = "boxed";  // boxed (terminal table) | tsv | csv
    std::string file;              // empty => stdout
};

// Run a query through the shared libxsql script path (which threads the
// runtime_settings query timeout, exactly like the HTTP/MCP servers) and render the
// result in the requested format to stdout or a file. Replaces the old db.exec +
// bespoke TablePrinter path, whose db.exec callback had no timeout hook.
static bool execute_query(xsql::Database& db, const char* sql,
                          const OutputOptions& out = {}) {
    xsql::ScriptOptions sopts;
    sopts.timeout_ms = pdbsql::runtime_settings().query_timeout_ms();

    xsql::ScriptResult script = pdbsql::run_pdbsql_script(db, sql, sopts);

    if (!script.parse_error.empty()) {
        fprintf(stderr, "SQL error: %s\n", script.parse_error.c_str());
        return false;
    }

    bool ok = true;
    for (const auto& stmt : script.results) {
        if (!stmt.success) {
            // Same contract as before: error on stderr.
            fprintf(stderr, "SQL error: %s\n", stmt.error.c_str());
            ok = false;
        }
    }

    const std::string body = pdbsql::format_script_result(script, out.format);
    if (!out.file.empty()) {
        FILE* fp = fopen(out.file.c_str(), "wb");
        if (!fp) {
            fprintf(stderr, "Error: cannot open output file: %s\n", out.file.c_str());
            return false;
        }
        if (!body.empty()) fwrite(body.data(), 1, body.size(), fp);
        fclose(fp);
        fprintf(stderr, "Wrote %zu bytes to %s\n", body.size(), out.file.c_str());
    } else {
        std::cout << body;
    }

    // Surface partial/timeout/warnings on stderr — never pollutes the data.
    //
    // A timed-out statement makes the CLI exit NON-ZERO. It used to return
    // `ok` (i.e. "the query itself did not error"), which reported a
    // truncated result as success: observed on a large PDB,
    // `--dump functions --format tsv -o out.tsv` at the default 60 s timeout
    // wrote a fraction of a percent of the table and exited 0.
    // The stderr warning was there, but a script doing
    // `pdbsql ... -o out.tsv 2>/dev/null && process out.tsv` (or any CI step
    // that checks only the exit status) silently consumed a 99.85%-incomplete
    // export as if it were complete. Truncated-but-reported-successful is the
    // worst possible outcome for a bulk export, so it now fails loudly; the
    // partial rows are still written and the warning still printed, so a
    // caller that WANTS a best-effort prefix can still use the file, it just
    // has to acknowledge the non-zero status deliberately.
    bool timed_out_any = false;
    for (const auto& stmt : script.results) {
        for (const auto& w : stmt.warnings) {
            fprintf(stderr, "Warning: %s\n", w.c_str());
        }
        if (stmt.timed_out) {
            fprintf(stderr, "Warning: query timed out; results are partial\n");
            timed_out_any = true;
        }
    }
    if (timed_out_any) {
        fprintf(stderr,
                "Error: result is INCOMPLETE (query timed out). Re-run with "
                "--query-timeout <sec> (0 = no limit) for a complete result.\n");
        return false;
    }
    return ok;
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
    printf("  %s --query-timeout <sec>             Seed runtime_settings.query_timeout_ms for the servers (0 = no limit; default 60)\n", prog);
    printf("  %s <pdb_file> --http --warm-file-index  Pay the line_numbers file_id warm-up (10-18s on a large PDB) at startup, not on the first query (also works with --mcp)\n", prog);
    printf("  %s <pdb_file> --http --warm-tables <list>  Pay the listed tables' one-time DIA enumeration warm-up at startup (comma-separated: functions,publics,data,udts,typedefs,enums,compilands -- also works with --mcp)\n", prog);
#endif
#ifdef PDBSQL_HAS_MCP
    printf("  %s <pdb_file> --mcp [port]           Start MCP server (default: random 9000-9999)\n", prog);
#endif
    printf("\nTables:\n");
    printf("  functions, publics, data, udts, udt_records, enums, enum_records, typedefs\n");
    printf("  thunks, labels, symbol_at(addr), compilands, source_files, line_numbers, sections\n");
    printf("  udt_fields, udt_methods, enum_values, base_classes, locals, parameters\n");
    printf("  runtime_settings (writable)\n");
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
    bool warm_file_index = false;
    std::vector<std::string> warm_tables;
    bool mcp_mode = false;
    int mcp_port = 0;  // 0 = random port in 9000-9999
    int query_timeout_sec = -1;  // -1 = flag not given (keep runtime_settings default)
    std::string output_format = "boxed";  // boxed | tsv | csv
    std::string output_file;              // -o/--output; empty => stdout
    bool quiet = false;                   // --quiet suppresses the banner
    std::string dump_table;               // --dump <table> => SELECT * FROM <table>

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
        } else if (strcmp(argv[i], "--warm-file-index") == 0) {
            warm_file_index = true;
        } else if (strcmp(argv[i], "--warm-tables") == 0 && i + 1 < argc) {
            warm_tables = split_warm_table_names(argv[++i]);
            for (const auto& name : warm_tables) {
                if (!pdbsql::symtag_for_warmable_table_name(name)) {
                    fprintf(stderr,
                            "Error: --warm-tables: unknown table '%s' -- valid tables are "
                            "functions, publics, data, udts, typedefs, enums, compilands\n",
                            name.c_str());
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_addr = argv[++i];
        } else if (strcmp(argv[i], "--query-timeout") == 0 && i + 1 < argc) {
            // strtol, not atoi: atoi("abc") is 0 (silently disables the cap and the
            // <0 guard never fires). Reject non-numeric/trailing garbage and cap at
            // the same one-hour ceiling enforced by RuntimeSettingsCore.
            const char* tv = argv[++i];
            char* tend = nullptr;
            long tsec = strtol(tv, &tend, 10);
            if (tend == tv || *tend != '\0' || tsec < 0 || tsec > 3600) {
                fprintf(stderr, "Invalid query timeout (expected 0..3600 seconds): %s\n", tv);
                return 1;
            }
            query_timeout_sec = static_cast<int>(tsec);
        } else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            output_format = argv[++i];
            if (output_format != "boxed" && output_format != "tsv" && output_format != "csv" &&
                output_format != "jsonl") {
                fprintf(stderr, "Invalid --format (expected boxed|tsv|csv|jsonl): %s\n", output_format.c_str());
                return 1;
            }
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--quiet") == 0) {
            quiet = true;
        } else if (strcmp(argv[i], "--dump") == 0 && i + 1 < argc) {
            dump_table = argv[++i];
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

    // --query-timeout is a startup override that seeds the shared
    // runtime_settings.query_timeout_ms (the HTTP/MCP servers read it per query).
    // Omitted => the family default (60000 ms); `--query-timeout 0` disables the
    // cap for a known-big dump. Runtime changes go through
    // `UPDATE runtime_settings` / `PRAGMA pdbsql.timeout_push`.
    if (query_timeout_sec >= 0) {
        if (!pdbsql::runtime_settings().set_query_timeout_ms(query_timeout_sec * 1000)) {
            fprintf(stderr, "Invalid query timeout: %d seconds\n", query_timeout_sec);
            return 1;
        }
    }

#ifdef PDBSQL_HAS_HTTP
    if (http_mode) {
        return run_http_mode(pdb_path, http_port, bind_addr, auth_token, warm_file_index, warm_tables);
    }
#else
    if (http_mode) {
        fprintf(stderr, "Error: HTTP mode not available. Rebuild with -DPDBSQL_WITH_HTTP=ON\n");
        return 1;
    }
#endif

#ifdef PDBSQL_HAS_MCP
    if (mcp_mode) {
        return run_mcp_mode(pdb_path, mcp_port, bind_addr, warm_file_index, warm_tables);
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

    // Banner on stderr (never stdout) so piped / `-o` output stays clean; --quiet drops it.
    if (!quiet) {
        fprintf(stderr, "pdbsql - Loaded: %s\n%s\n\n", pdb_path.c_str(), g_copyright);
    }

    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    // --dump <table> is sugar for "SELECT * FROM <table>" (pair with --format/-o for a
    // machine-readable bulk export). --query-timeout 0 lifts the safety net for a full
    // unbounded dump -- fine for a symbol table's cheap columns, but SELECT * pulls
    // `undecorated` too, whose demangle cost on a large table's real symbol names can run
    // to hours, not seconds (at the default timeout it returned a tiny fraction of
    // every function). Even the column-limited fast path still permanently commits
    // several GB of RAM to the process for a large table -- that cost comes from the
    // underlying engine realizing each symbol as it walks, not from the response size, and
    // is never released. See prompts/pdbsql_agent.md's "Aggregates"/bulk-export section for
    // the full guidance.
    if (!dump_table.empty()) {
        bool valid = true;
        for (char c : dump_table) {
            const bool ok_char = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                 (c >= '0' && c <= '9') || c == '_';
            if (!ok_char) { valid = false; break; }
        }
        if (!valid) {
            fprintf(stderr, "Invalid --dump table name: %s\n", dump_table.c_str());
            return 1;
        }
        query = "SELECT * FROM " + dump_table;
    }

    OutputOptions out_opts{output_format, output_file};
    if (!query.empty()) {
        if (!execute_query(db, query.c_str(), out_opts)) {
            return 1;
        }
    } else if (interactive) {
        interactive_mode(db);
    } else {
        dump_symbol_counts(session);
    }

    return 0;
}
