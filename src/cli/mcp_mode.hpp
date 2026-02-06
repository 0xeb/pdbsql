#pragma once

#ifdef PDBSQL_HAS_AI_AGENT

#include <string>

int run_mcp_mode(const std::string& pdb_path, int port,
                 const std::string& provider_override, bool verbose);

#endif
