// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#ifdef PDBSQL_HAS_HTTP

#include <string>

int run_http_mode(const std::string& pdb_path, int port,
                  const std::string& bind_addr, const std::string& auth_token);

#endif
