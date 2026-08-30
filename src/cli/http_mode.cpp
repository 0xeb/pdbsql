// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "http_mode.hpp"

#ifdef PDBSQL_HAS_HTTP

#include "query_json.hpp"
#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include "../common/http_server.hpp"

#include <xsql/database.hpp>

#include <chrono>
#include <csignal>
#include <string>
#include <thread>
#include <vector>

static pdbsql::PdbsqlHTTPServer* g_http_server = nullptr;

static void http_signal_handler(int) {
    if (g_http_server) g_http_server->stop();
}

// The shared http_query_server parses X-XSQL-Timeout into opts.timeout_ms
// when the client sends it, but has no notion of pdbsql's own server-side
// default (--query-timeout, seeded into runtime_settings). opts.timeout_ms
// stays 0 (its ScriptOptions default) when the header is absent, so apply
// the runtime_settings default exactly then -- matching the pre-consolidation
// behavior where this server always had SOME bound unless a client explicitly
// asked for none.
static xsql::ScriptOptions with_default_timeout(const xsql::ScriptOptions& opts) {
    if (opts.timeout_ms != 0) return opts;
    xsql::ScriptOptions effective = opts;
    effective.timeout_ms = pdbsql::runtime_settings().query_timeout_ms();
    return effective;
}

// A timed-out statement comes back from the shared core with the bare error
// "Query timed out" (libxsql's query_script.hpp) -- accurate, but it leaves an
// operator with no idea that the query is answerable at all, or how. Several
// ordinary questions on a large PDB genuinely exceed the 60 s family-default
// timeout, so out of the box the operator sees only "Query timed out" for a
// question that WOULD succeed with a larger bound.
//
// Attach the remedy as a WARNING rather than rewriting the error: the error
// string is the shared core's contract (every family tool returns the same
// text, and clients may match on it), while `warnings` is the established
// channel for advisory context and is already surfaced by the JSON envelope,
// the CLI, and the streaming paths. This keeps the fix entirely inside pdbsql
// -- no libxsql change, so no 6-consumer re-verification -- while still telling
// the operator what to do next.
static void annotate_timeout_guidance(xsql::ScriptResult& script) {
    for (auto& stmt : script.results) {
        if (!stmt.timed_out) continue;
        stmt.warnings.push_back(
            "pdbsql: this query exceeded the query timeout. Retry with a larger "
            "bound -- send an 'X-XSQL-Timeout: <ms>' header (e.g. 180000), or "
            "start the server with --query-timeout <sec> (0 = no limit). Whole-table "
            "questions over udts/enums on a large PDB commonly need 60-120s; see "
            "the Performance section of the agent prompt for the fast alternatives.");
    }
}

int run_http_mode(const std::string& pdb_path, int port, const std::string& bind_addr,
                  const std::string& auth_token, bool warm_file_index,
                  const std::vector<std::string>& warm_tables) {
    // Open PDB
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("PDBSQL HTTP Server - Loaded: %s\n", pdb_path.c_str());

    // Opt-in: pay line_numbers' WHERE file_id=X one-time DIA index warm-up
    // 
    // here at startup instead of on whichever client's query happens to touch
    // file_id first. X-XSQL-Timeout cannot cut this short
    // either way  --
    // this flag only moves WHERE the cost lands, from an unpredictable first
    // request to a predictable startup delay, for operators who'd rather have
    // that tradeoff than a slow/timed-out first file_id query in production.
    if (warm_file_index) {
        printf("Warming line_numbers file_id index...\n");
        fflush(stdout);
        const auto warm_t0 = std::chrono::steady_clock::now();
        session.ensure_file_index_warm();
        const double warm_sec =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - warm_t0).count();
        printf("File index warm in %.2fs\n", warm_sec);
    }

    // Opt-in: pay the listed tables' one-time DIA enumeration warm-up (seconds
    // per table on a large PDB) here at startup instead of on whichever
    // client's query happens to touch that table first. Same tradeoff as
    // --warm-file-index: moves an unpredictable slow-first-query cost to a
    // predictable startup delay. main.cpp
    // already validated every name in warm_tables against
    // symtag_for_warmable_table_name(), so this loop only sees known-good
    // table names.
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

    // Create database and register tables
    xsql::Database db;
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    pdbsql::PdbsqlHTTPServer http_server;
    g_http_server = &http_server;

    auto old_handler = std::signal(SIGINT, http_signal_handler);
#ifdef _WIN32
    auto old_break_handler = std::signal(SIGBREAK, http_signal_handler);
#else
    auto old_term_handler = std::signal(SIGTERM, http_signal_handler);
#endif

    const int actual_port = http_server.start(
        port,
        [&db](const std::string& sql, const xsql::ScriptOptions& opts) {
            auto script = pdbsql::run_pdbsql_script(db, sql, with_default_timeout(opts));
            annotate_timeout_guidance(script);
            return script;
        },
        bind_addr, /*use_queue=*/false, auth_token, pdb_path,
        [&db](const std::string& sql, const xsql::ScriptOptions& raw_opts, bool ndjson,
              const pdbsql::HTTPStreamSink& sink) {
            const xsql::ScriptOptions opts = with_default_timeout(raw_opts);
            // Product PRAGMAs (timeout_push/pop) can't be intercepted by the
            // generic row-by-row streamer, so route those scripts through the
            // PRAGMA-aware executor and emit the adapted result as one chunk;
            // ordinary data-only scripts get true O(one-row) streaming below.
            if (pdbsql::script_has_runtime_pragma(sql)) {
                auto script = pdbsql::run_pdbsql_script(db, sql, opts);
                annotate_timeout_guidance(script);
                const std::string body = ndjson
                    ? xsql::script_result_to_jsonl(script)
                    : xsql::script_result_to_json(script, opts.include_sql);
                (void)sink(body.data(), body.size());
            } else if (ndjson) {
                xsql::stream_database_script_ndjson(db, sql, opts, sink);
            } else {
                xsql::stream_database_script_json(db, sql, opts, sink);
            }
        });

    if (actual_port <= 0) {
        fprintf(stderr, "Error: failed to start HTTP server\n");
        std::signal(SIGINT, old_handler);
#ifdef _WIN32
        std::signal(SIGBREAK, old_break_handler);
#else
        std::signal(SIGTERM, old_term_handler);
#endif
        g_http_server = nullptr;
        return 1;
    }

    printf("HTTP server listening on http://%s:%d\n",
           bind_addr.empty() ? "127.0.0.1" : bind_addr.c_str(), actual_port);
    printf("Endpoints: /help, /query, /cancel, /status, /shutdown\n");
    printf("Example: curl http://localhost:%d/help\n", actual_port);
    printf("Press Ctrl+C to stop.\n\n");
    fflush(stdout);

    // Block until server stops (via signal or /shutdown)
    while (http_server.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

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
