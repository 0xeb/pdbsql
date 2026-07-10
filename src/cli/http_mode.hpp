// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#ifdef PDBSQL_HAS_HTTP

#include <string>

int run_http_mode(const std::string& pdb_path, int port,
                  const std::string& bind_addr, const std::string& auth_token);

#endif
