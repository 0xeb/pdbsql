#pragma once

#include <xsql/socket/client.hpp>
#include <string>

void print_remote_result(const xsql::socket::RemoteResult& qr);

bool parse_port(const std::string& s, int& port);

int run_remote_mode(const std::string& host, int port,
                    const std::string& query, const std::string& auth_token,
                    bool interactive);
