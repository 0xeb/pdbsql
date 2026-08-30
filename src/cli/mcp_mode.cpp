// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "mcp_mode.hpp"

#ifdef PDBSQL_HAS_MCP

#include "query_json.hpp"
#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include "../common/mcp_server.hpp"

#include <xsql/database.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string>
#include <vector>

static std::atomic<bool> g_mcp_quit{false};

static void mcp_signal_handler(int) {
    g_mcp_quit.store(true);
}

// Serve the pdbsql_query MCP tool over SSE until Ctrl+C. The SSE server calls the
// query callback on its own thread; use_queue=true drains commands on this thread.
int run_mcp_mode(const std::string& pdb_path, int port, const std::string& bind_addr,
                 bool warm_file_index, const std::vector<std::string>& warm_tables) {
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("PDBSQL MCP Server - Loaded: %s\n", pdb_path.c_str());

    // See run_http_mode's identical block (http_mode.cpp) for the full
    // rationale: an opt-in one-time DIA index warm-up for line_numbers'
    // WHERE file_id=X pushdown, paid at startup instead of on whichever
    // client's query touches it first.
    if (warm_file_index) {
        printf("Warming line_numbers file_id index...\n");
        fflush(stdout);
        const auto warm_t0 = std::chrono::steady_clock::now();
        session.ensure_file_index_warm();
        const double warm_sec =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - warm_t0).count();
        printf("File index warm in %.2fs\n", warm_sec);
    }

    // See run_http_mode's identical block (http_mode.cpp) for the full
    // rationale: an opt-in one-time DIA enumeration warm-up for each listed
    // table, paid at startup instead of on whichever client's query
    // touches it first.
    for (const auto& table_name : warm_tables) {
        auto tag = pdbsql::symtag_for_warmable_table_name(table_name);
        printf("Warming %s table...\n", table_name.c_str());
        fflush(stdout);
        const auto warm_t0 = std::chrono::steady_clock::now();
        session.ensure_symtag_warm(*tag);
        const double warm_sec =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - warm_t0).count();
        printf("%s table warm in %.2fs\n", table_name.c_str(), warm_sec);
    }

    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    std::string actual_bind = bind_addr.empty() ? "127.0.0.1" : bind_addr;

    // Direct-SQL executor (returns the canonical JSON envelope for MCP). Honors
    // the shared runtime_settings.query_timeout_ms (read fresh per call).
    pdbsql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
        xsql::ScriptOptions sopts;
        sopts.timeout_ms = pdbsql::runtime_settings().query_timeout_ms();
        return query_result_to_json(db, sql, sopts);
    };

    pdbsql::PdbsqlMCPServer mcp_server;
    int actual_port = mcp_server.start(port, sql_cb, actual_bind, true);
    if (actual_port <= 0) {
        fprintf(stderr, "Error: Failed to start MCP server on port %d\n", port);
        return 1;
    }

    printf("%s", pdbsql::format_mcp_info(actual_port).c_str());
    printf("Press Ctrl+C to stop.\n\n");
    fflush(stdout);

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

#endif // PDBSQL_HAS_MCP
