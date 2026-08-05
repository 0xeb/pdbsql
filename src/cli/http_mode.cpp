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

#include <xsql/database.hpp>
#include <xsql/thinclient/server.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
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
  POST /cancel   - Cancel the in-flight query (it returns its partial rows)
  GET  /status   - Server health
  POST /shutdown - Stop server

POST /query headers:
  X-XSQL-Stream: 1       - stream the JSON envelope row-by-row (chunked; use curl -N)
  X-XSQL-Stream: ndjson  - stream one JSON object per row per line (NDJSON)
  X-XSQL-Timeout: <ms>   - bound this request (0 = no limit)

Tables:
  functions       - Functions with RVA, size, section info
  symbol_at(addr) - TVF: innermost symbol containing an address (addr -> symbol)
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
  SELECT name, rva, length FROM functions ORDER BY length DESC LIMIT 10;
  SELECT name, kind FROM symbol_at(0x14002A1F0);   -- symbol at an address
  SELECT name FROM udts LIMIT 10;
  SELECT * FROM sections;

Response Format (multi-statement envelope):
  {"results": [{"success": true, "columns": [...], "rows": [[...]], "row_count": N},
               {"success": false, "error": "message"}, ...],
   "statement_count": M, "row_count_total": T, "first_error_index": null}
  results[] holds one object per statement; first_error_index is the index of the first
  failed statement (null if all succeeded).

Authentication (if enabled):
  Header: Authorization: Bearer <token>
  Or:     X-XSQL-Token: <token>

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
        fprintf(stderr, "WARNING: Binding to non-loopback address %s\n", bind_addr.c_str());
        if (auth_token.empty()) {
            fprintf(stderr, "WARNING: No authentication token set. Server is accessible without authentication.\n");
            fprintf(stderr, "         Consider using --token <secret> for remote access.\n");
        }
    }

    std::mutex query_mutex;
    // Server-wide cancel flag. POST /cancel sets it (on its own httplib worker
    // thread); the in-flight /query — which holds query_mutex on a different worker —
    // observes it via ScriptOptions::should_cancel and bails with partial rows. It is
    // reset to false under query_mutex at the start of each query, so a stale cancel
    // never bleeds into the next one. This is the root fix for a runaway query
    // poisoning the serial server (the X-XSQL-Timeout bound is the softer mitigation).
    std::atomic<bool> cancel_requested{false};

    cfg.setup_routes = [&db, &pdb_path, &auth_token, &query_mutex, &cancel_requested, port](httplib::Server& svr) {
        svr.Get("/", [port](const httplib::Request&, httplib::Response& res) {
            std::string welcome = "PDBSQL HTTP Server\n\nEndpoints:\n"
                "  GET  /help     - API documentation\n"
                "  POST /query    - Execute SQL query\n"
                "  POST /cancel   - Cancel in-flight query\n"
                "  GET  /status   - Health check\n"
                "  POST /shutdown - Stop server\n\n"
                "Example: curl -X POST http://localhost:" + std::to_string(port) + "/query -d \"SELECT name FROM functions LIMIT 5\"\n";
            res.set_content(welcome, "text/plain");
        });

        svr.Get("/help", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(PDBSQL_HELP_TEXT, "text/plain");
        });

        svr.Post("/query", [&db, &auth_token, &query_mutex, &cancel_requested](const httplib::Request& req, httplib::Response& res) {
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

            // Per-request timeout from the shared runtime_settings (read fresh, so
            // an UPDATE runtime_settings / PRAGMA takes effect immediately). Both
            // paths reuse the same libxsql machinery via ScriptOptions::timeout_ms.
            xsql::ScriptOptions sopts;
            sopts.timeout_ms = pdbsql::runtime_settings().query_timeout_ms();

            // Optional per-request override: `X-XSQL-Timeout: <ms>` (0 = no limit).
            // Lets a client bound an individual query even when the server default is
            // unlimited (--query-timeout 0), without a global UPDATE runtime_settings.
            if (req.has_header("X-XSQL-Timeout")) {
                try {
                    const long ms = std::stol(req.get_header_value("X-XSQL-Timeout"));
                    if (ms >= 0) sopts.timeout_ms = static_cast<int>(ms);
                } catch (...) { /* invalid header: keep the runtime_settings default */ }
            }

            // Wire the server-wide cancel flag so POST /cancel aborts this query even
            // under --query-timeout 0 (the deadline above still applies when set). The
            // flag is reset under query_mutex just before the query runs (below).
            sopts.should_cancel = [&cancel_requested]() { return cancel_requested.load(); };

            // Opt-in streaming: `X-XSQL-Stream: 1` streams the result envelope
            // row-by-row via a chunked response, so a multi-million-row dump never
            // materializes a whole JSON string in RAM. `X-XSQL-Stream: ndjson` instead
            // streams one JSON object per row per line (no envelope). The chunked
            // provider runs on the worker thread AFTER this handler returns, so the
            // query_mutex must be taken INSIDE the provider — a handler-scoped lock
            // would already be released when streaming starts.
            const std::string stream_hdr = req.has_header("X-XSQL-Stream")
                                               ? req.get_header_value("X-XSQL-Stream") : std::string();
            const bool stream_ndjson = (stream_hdr == "ndjson");
            const bool stream = stream_ndjson || stream_hdr == "1" || stream_hdr == "true";
            if (stream) {
                std::string sql = req.body;
                res.set_chunked_content_provider(
                    stream_ndjson ? "application/x-ndjson" : "application/json",
                    [&db, &query_mutex, &cancel_requested, sql, sopts, stream_ndjson](size_t, httplib::DataSink& sink) {
                        std::lock_guard<std::mutex> lock(query_mutex);
                        cancel_requested.store(false);  // fresh per in-flight query, under the lock
                        // Propagate the sink's disconnect signal (write() == false) so a
                        // client that drops mid-stream aborts the query promptly.
                        auto out = [&sink](const char* d, std::size_t n) { return sink.write(d, n); };
                        if (pdbsql::script_has_runtime_pragma(sql)) {
                            // The generic streaming executor cannot intercept
                            // product PRAGMAs. Preserve their semantics by
                            // emitting the product-adapted result as one chunk;
                            // ordinary data-only scripts retain O(one-row)
                            // streaming below.
                            const auto script = pdbsql::run_pdbsql_script(db, sql, sopts);
                            const std::string body = stream_ndjson
                                ? xsql::script_result_to_jsonl(script)
                                : xsql::script_result_to_json(script, sopts.include_sql);
                            (void)out(body.data(), body.size());
                        } else if (stream_ndjson) {
                            xsql::stream_database_script_ndjson(db, sql, sopts, out);
                        } else {
                            xsql::stream_database_script_json(db, sql, sopts, out);
                        }
                        sink.done();
                        return true;
                    });
                return;
            }

            std::lock_guard<std::mutex> lock(query_mutex);
            cancel_requested.store(false);  // fresh per in-flight query, under the lock
            res.set_content(query_result_to_json(db, req.body, sopts), "application/json");
        });

        svr.Get("/status", [&pdb_path](const httplib::Request&, httplib::Response& res) {
            // Unauthenticated liveness probe (exempt from --token, like /help): it
            // exposes no PDB data and NEVER touches DIA (no COUNT(*) that could peg a
            // core for minutes while holding query_mutex), so uptime/LB/health probes
            // work without the token and a slow query can't starve them.
            res.set_content("{\"success\":true,\"status\":\"ok\",\"tool\":\"pdbsql\",\"pdb\":\"" + json_escape(pdb_path) + "\"}", "application/json");
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

        svr.Post("/cancel", [&auth_token, &cancel_requested](const httplib::Request& req, httplib::Response& res) {
            // Auth-guarded like /query and /shutdown. Sets the server-wide cancel flag;
            // the in-flight /query (running on another worker thread, holding
            // query_mutex) observes it via should_cancel and returns its partial rows.
            // Tokenless in intent — it targets whatever query is currently executing.
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
            cancel_requested.store(true);
            res.set_content("{\"success\":true,\"message\":\"cancel requested\"}", "application/json");
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

    http_server.run_async();
    int actual_port = http_server.port();

    printf("HTTP server listening on http://%s:%d\n", cfg.bind_address.c_str(), actual_port);
    printf("Endpoints: /help, /query, /status, /shutdown\n");
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
