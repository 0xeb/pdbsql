// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#ifdef PDBSQL_HAS_MCP

#include <string>
#include <vector>

int run_mcp_mode(const std::string& pdb_path, int port, const std::string& bind_addr,
                 bool warm_file_index = false,
                 const std::vector<std::string>& warm_tables = {});

#endif
