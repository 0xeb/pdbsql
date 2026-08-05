// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
// pdb_runtime_settings.hpp - process-wide runtime settings for pdbsql.

#include <xsql/runtime_settings.hpp>

namespace pdbsql {

// pdbsql has no product-specific runtime keys, so it uses the shared
// xsql::runtime::RuntimeSettingsCore directly (like ghidrasql/r2sql), exposed as
// a process singleton (like idasql/bnsql's runtime_settings()). query_timeout_ms
// defaults to the family standard 60000 ms; callers read it fresh and pass it as
// ScriptOptions::timeout_ms / QueryOptions::timeout_ms per query.
inline xsql::runtime::RuntimeSettingsCore& runtime_settings() {
    static xsql::runtime::RuntimeSettingsCore instance;
    return instance;
}

}  // namespace pdbsql
