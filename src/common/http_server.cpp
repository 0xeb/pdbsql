// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "http_server.hpp"
#include "pdbsql_agent_prompt.hpp"

#include <cstdio>
#include <sstream>

#ifdef PDBSQL_HAS_HTTP

namespace pdbsql {

static std::string build_http_help_text() {
    std::ostringstream out;
    out << "PDBSQL HTTP REST API\n"
        << "====================\n\n"
        << "SQL interface for Windows PDB debug symbols via HTTP.\n\n"
        << "Endpoints:\n"
        << "  GET  /         - Welcome message\n"
        << "  GET  /help     - This documentation (the full AI-agent reference)\n"
        << "  POST /query    - Execute SQL (body = raw SQL, response = JSON)\n"
        << "  POST /cancel   - Cancel the in-flight query (it returns its partial rows)\n"
        << "  GET  /status   - Server health\n"
        << "  POST /shutdown - Stop server\n\n"
        << "POST /query headers:\n"
        << "  X-XSQL-Stream: 1       - stream the JSON envelope row-by-row (chunked; use curl -N)\n"
        << "  X-XSQL-Stream: ndjson  - stream one JSON object per row per line (NDJSON)\n"
        << "  X-XSQL-Timeout: <ms>   - bound this request (0 = no limit)\n\n"
        << "Response Format (multi-statement envelope):\n"
        << "  {\"results\": [{\"success\": true, \"columns\": [...], \"rows\": [[...]], \"row_count\": N},\n"
        << "               {\"success\": false, \"error\": \"message\"}, ...],\n"
        << "   \"statement_count\": M, \"row_count_total\": T, \"first_error_index\": null}\n"
        << "  results[] holds one object per statement; first_error_index is the index of the first\n"
        << "  failed statement (null if all succeeded).\n\n"
        << "Authentication (if enabled):\n"
        << "  Header: Authorization: Bearer <token>\n"
        << "  Or:     X-XSQL-Token: <token>\n\n"
        << "PDBSQL /help \xE2\x80\x94 AI agent reference\n\n"
        << "This is the complete, canonical reference for using PDBSQL optimally (tables,\n"
        << "query patterns, performance notes, server modes). It is written for AI agents,\n"
        << "not casual human browsing:\n\n"
        << AGENT_PROMPT_TEXT;
    return out.str();
}

int PdbsqlHTTPServer::start(int port, HTTPQueryCallback query_cb,
                             const std::string& bind_addr, bool use_queue,
                             const std::string& auth_token, const std::string& pdb_path,
                             HTTPStreamingCallback streaming_cb) {
    if (impl_ && impl_->is_running()) {
        return impl_->port();
    }

    const std::string effective_bind_addr = bind_addr.empty() ? "127.0.0.1" : bind_addr;

    if (auth_token.empty()
        && effective_bind_addr != "127.0.0.1" && effective_bind_addr != "localhost"
        && effective_bind_addr != "::1") {
        std::fprintf(stderr,
            "WARNING: pdbsql HTTP server bound to non-loopback address %s with no "
            "authentication.\n         The SQL endpoint is reachable by other hosts. "
            "Prefer 127.0.0.1 or set --token.\n",
            effective_bind_addr.c_str());
    }

    xsql::thinclient::http_query_server_config config;
    config.tool_name = "pdbsql";
    config.help_text = build_http_help_text();
    config.port = port;
    config.bind_address = effective_bind_addr;
    // script_executor (not query_fn) keeps ScriptOptions live through the run,
    // which is what makes /cancel and X-XSQL-Timeout work.
    config.script_executor = std::move(query_cb);
    if (streaming_cb) config.streaming_executor = std::move(streaming_cb);
    config.use_queue = use_queue;
    // DIA/COM isn't concurrency-safe.
    config.serialize_requests = !use_queue;
    if (!auth_token.empty()) config.auth_token = auth_token;
    // Must stay unauthenticated even with --token set (health/LB probes).
    // Regression of record: shipped in dfa9eda, silently reverted by 704733b
    // the next day -- surface_e2e.py's "Auth: GET /status unauth exempt" guards it.
    config.status_requires_auth = false;
    config.status_fn = [pdb_path]() {
        return xsql::json{{"mode", "http"}, {"pdb", pdb_path}};
    };

    impl_ = std::make_unique<xsql::thinclient::http_query_server>(config);
    return impl_->start();
}

void PdbsqlHTTPServer::run_until_stopped() {
    if (impl_) impl_->run_until_stopped();
}

void PdbsqlHTTPServer::stop() {
    if (impl_) {
        impl_->stop();
        impl_.reset();
    }
}

void PdbsqlHTTPServer::set_interrupt_check(std::function<bool()> check) {
    if (impl_) impl_->set_interrupt_check(std::move(check));
}

std::string format_http_info(int port) {
    return xsql::thinclient::format_http_info("pdbsql", port);
}

std::string format_http_status(int port, bool running) {
    return xsql::thinclient::format_http_status(port, running);
}

} // namespace pdbsql

#endif // PDBSQL_HAS_HTTP
