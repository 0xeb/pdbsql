#pragma once

#ifdef PDBSQL_HAS_HTTP

#include <string>

int run_http_mode(const std::string& pdb_path, int port,
                  const std::string& bind_addr, const std::string& auth_token);

#endif
