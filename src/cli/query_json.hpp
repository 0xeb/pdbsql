// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/database.hpp>
#include <xsql/query_script.hpp>
#include <xsql/runtime_settings.hpp>
#include "pdb_runtime_settings.hpp"
#include <string>
#include <sstream>
#include <cstdio>

inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 10);
    for (char ch : s) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(ch));
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
    return out;
}

namespace pdbsql {

// Execute through the product adapter rather than directly through
// xsql::run_database_script so the two canonical imperative PRAGMAs are real
// operations instead of SQLite's silent unknown-PRAGMA no-op.
inline xsql::ScriptResult run_pdbsql_script(
        xsql::Database& db, const std::string& script,
        const xsql::ScriptOptions& options = {}) {
    int effective_timeout_ms = options.timeout_ms;
    return xsql::run_script(
        script, options,
        [&db, &options, &effective_timeout_ms](
                const std::string& sql, xsql::ScriptStatementResult& out) {
            const auto request =
                xsql::runtime::parse_runtime_pragma(sql.c_str(), "pdbsql");
            if (request.matched) {
                const auto reply =
                    (request.key == "timeout_push" || request.key == "timeout_pop")
                        ? xsql::runtime::handle_common_runtime_pragma(
                              request, "pdbsql", runtime_settings())
                        : xsql::runtime::pragma_error(
                              xsql::runtime::unknown_runtime_pragma_error("pdbsql"));
                out.success = reply.success;
                out.error = reply.error;
                if (reply.success) {
                    out.columns = {"name", "value"};
                    out.rows = {{reply.name, reply.value}};
                    out.cell_null = {{0, 0}};
                    effective_timeout_ms = runtime_settings().query_timeout_ms();
                }
                return;
            }

            xsql::QueryOptions qopts;
            qopts.timeout_ms = effective_timeout_ms;
            qopts.should_cancel = options.should_cancel;
            xsql::Result result = db.query(sql, qopts);
            out.columns = std::move(result.columns);
            out.rows.reserve(result.rows.size());
            out.cell_null.reserve(result.rows.size());
            for (auto& row : result.rows) {
                out.rows.push_back(std::move(row.values));
                out.cell_null.push_back(std::move(row.nulls));
            }
            out.elapsed_ms = static_cast<double>(result.elapsed_ms);
            out.success = result.error.empty();
            out.error = std::move(result.error);
            out.timed_out = result.timed_out;
            out.partial = result.partial;
            out.warnings = std::move(result.warnings);
        });
}

inline bool script_has_runtime_pragma(const std::string& script) {
    std::vector<std::string> statements;
    std::string error;
    if (!xsql::collect_statements(script, statements, error)) {
        return false;
    }
    for (const auto& statement : statements) {
        if (xsql::runtime::parse_runtime_pragma(
                statement.c_str(), "pdbsql").matched) {
            return true;
        }
    }
    return false;
}

}  // namespace pdbsql

// Multi-statement aware: returns the canonical xsql script envelope. Single
// statement is array-of-one — no legacy single-shape fallback.
inline std::string query_result_to_json(xsql::Database& db, const std::string& sql,
                                        const xsql::ScriptOptions& options = {}) {
    auto script = pdbsql::run_pdbsql_script(db, sql, options);
    return xsql::script_result_to_json(script, options.include_sql);
}
