// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <xsql/database.hpp>
#include <xsql/query_script.hpp>
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

// Multi-statement aware: returns the canonical xsql script envelope.
// Single statement is array-of-one — no legacy single-shape fallback.
inline std::string query_result_to_json(xsql::Database& db, const std::string& sql,
                                        const xsql::ScriptOptions& options = {}) {
    auto script = xsql::run_database_script(db, sql, options);
    return xsql::script_result_to_json(script, options.include_sql);
}
