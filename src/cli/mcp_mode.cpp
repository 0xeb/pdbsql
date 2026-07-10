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
#include <csignal>
#include <cstdio>
#include <string>

static std::atomic<bool> g_mcp_quit{false};

static void mcp_signal_handler(int) {
    g_mcp_quit.store(true);
}

// Serve the pdbsql_query MCP tool over SSE until Ctrl+C. The SSE server calls the
// query callback on its own thread; use_queue=true drains commands on this thread.
int run_mcp_mode(const std::string& pdb_path, int port, const std::string& bind_addr) {
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("PDBSQL MCP Server - Loaded: %s\n", pdb_path.c_str());

    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    std::string actual_bind = bind_addr.empty() ? "127.0.0.1" : bind_addr;

    // Direct-SQL executor (returns the canonical JSON envelope for MCP)
    pdbsql::QueryCallback sql_cb = [&db](const std::string& sql) -> std::string {
        return query_result_to_json(db, sql);
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
