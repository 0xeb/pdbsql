// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

/**
 * PdbsqlHTTPServer - HTTP REST server for PDBSQL REPL
 *
 * Thin wrapper over xsql::thinclient::http_query_server.
 * Preserves the existing API for backward compatibility.
 */

#ifdef PDBSQL_HAS_HTTP

#include <xsql/thinclient/http_query_server.hpp>

#include <string>
#include <functional>
#include <memory>

namespace pdbsql {

// Callback for handling SQL queries
using HTTPQueryCallback = std::function<std::string(const std::string& sql)>;

class PdbsqlHTTPServer {
public:
    PdbsqlHTTPServer() = default;
    ~PdbsqlHTTPServer() { stop(); }

    // Non-copyable
    PdbsqlHTTPServer(const PdbsqlHTTPServer&) = delete;
    PdbsqlHTTPServer& operator=(const PdbsqlHTTPServer&) = delete;

    int start(int port, HTTPQueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1",
              bool use_queue = false);

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
