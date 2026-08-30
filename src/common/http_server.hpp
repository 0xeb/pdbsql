// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// The live HTTP transport for `pdbsql --http`; thin wrapper over the shared
// xsql::thinclient::http_query_server.

#ifdef PDBSQL_HAS_HTTP

#include <xsql/thinclient/http_query_server.hpp>

#include <string>
#include <functional>
#include <memory>

namespace pdbsql {

using HTTPQueryCallback = std::function<xsql::ScriptResult(
    const std::string& sql, const xsql::ScriptOptions& options)>;

using HTTPStreamSink = xsql::thinclient::http_query_server_config::stream_sink_t;

// True chunked streaming: bounded-memory output (a live DIA cursor), not a
// materialized ScriptResult.
using HTTPStreamingCallback = std::function<void(
    const std::string& sql, const xsql::ScriptOptions& options,
    bool ndjson, const HTTPStreamSink& sink)>;

class PdbsqlHTTPServer {
public:
    PdbsqlHTTPServer() = default;
    ~PdbsqlHTTPServer() { stop(); }

    PdbsqlHTTPServer(const PdbsqlHTTPServer&) = delete;
    PdbsqlHTTPServer& operator=(const PdbsqlHTTPServer&) = delete;

    // port 0 = random 8100-8999. streaming_cb is optional (chunked
    // X-XSQL-Stream responses). Returns the actual port, or -1 on failure.
    int start(int port, HTTPQueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1",
              bool use_queue = false,
              const std::string& auth_token = "",
              const std::string& pdb_path = "",
              HTTPStreamingCallback streaming_cb = nullptr);

    void run_until_stopped();
    void stop();

    bool is_running() const { return impl_ && impl_->is_running(); }
    int port() const { return impl_ ? impl_->port() : 0; }
    std::string url() const { return impl_ ? impl_->url() : ""; }

    void set_interrupt_check(std::function<bool()> check);

private:
    std::unique_ptr<xsql::thinclient::http_query_server> impl_;
};

std::string format_http_info(int port);
std::string format_http_status(int port, bool running);

} // namespace pdbsql

#endif // PDBSQL_HAS_HTTP
