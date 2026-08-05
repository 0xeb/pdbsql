// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
// cli_render.hpp - render a query statement result as pdbsql's boxed CLI table,
// via the shared libxsql renderer (no bespoke table printer).

#include <xsql/query_script.hpp>       // ScriptStatementResult, is_null_cell
#include <xsql/cli/table_printer.hpp>  // xsql::cli::print_table + TableStyle::boxed

#include <cstddef>
#include <string>
#include <vector>

namespace pdbsql {

// Render one successful statement as the classic boxed `+---+ | |` table with the
// `N row(s)` footer, using libxsql's shared `print_table`. A real SQL NULL prints
// as the text "NULL" (matching the historical CLI, distinguished from an
// empty-string cell via is_null_cell). A column-less result or a 0-row SELECT
// prints NOTHING — the historical behavior — so callers need no extra guard.
inline std::string render_statement(const xsql::ScriptStatementResult& stmt) {
    if (stmt.columns.empty() || stmt.rows.empty()) return {};

    std::vector<std::vector<std::string>> rows;
    rows.reserve(stmt.rows.size());
    for (std::size_t ri = 0; ri < stmt.rows.size(); ++ri) {
        std::vector<std::string> row;
        row.reserve(stmt.rows[ri].size());
        for (std::size_t ci = 0; ci < stmt.rows[ri].size(); ++ci) {
            row.push_back(stmt.is_null_cell(ri, ci) ? std::string("NULL")
                                                    : stmt.rows[ri][ci]);
        }
        rows.push_back(std::move(row));
    }

    xsql::cli::TablePrintOptions opts;
    opts.style = xsql::cli::TableStyle::boxed;   // boxed_row_count_footer defaults true
    return xsql::cli::print_table(stmt.columns, rows, opts);
}

// Render a whole script result in the requested CLI format. "tsv"/"csv"/"jsonl" reuse
// libxsql's shared formatters (no padding, no box drawing, no banner — directly
// parseable for scripting); anything else falls back to the boxed per-statement
// tables (with a blank line between statements). Used by the one-shot query path
// and `--dump`/`--format`.
inline std::string format_script_result(const xsql::ScriptResult& script,
                                        const std::string& fmt) {
    if (fmt == "tsv") return xsql::script_result_to_tsv(script);
    if (fmt == "csv") return xsql::script_result_to_csv(script);
    if (fmt == "jsonl") return xsql::script_result_to_jsonl(script);
    std::string out;
    bool wrote_table = false;
    for (const auto& stmt : script.results) {
        if (!stmt.success) continue;
        const std::string table = render_statement(stmt);
        if (!table.empty()) {
            if (wrote_table) out += "\n";  // blank line between statements
            out += table;
            wrote_table = true;
        }
    }
    return out;
}

}  // namespace pdbsql
