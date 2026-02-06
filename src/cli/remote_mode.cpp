#include "remote_mode.hpp"
#include "table_printer.hpp"

#include <xsql/socket/client.hpp>

#include <iostream>
#include <string>

void print_remote_result(const xsql::socket::RemoteResult& qr) {
    if (qr.rows.empty() && qr.columns.empty()) {
        std::cout << "OK\n";
        return;
    }
    TablePrinter printer;
    printer.set_columns(qr.columns);
    for (const auto& row : qr.rows) {
        printer.add_row(row.values);
    }
    printer.print();
}

bool parse_port(const std::string& s, int& port) {
    try {
        size_t idx = 0;
        int v = std::stoi(s, &idx, 10);
        if (idx != s.size()) return false;
        if (v < 1 || v > 65535) return false;
        port = v;
        return true;
    } catch (...) {
        return false;
    }
}

int run_remote_mode(const std::string& host, int port,
                    const std::string& query, const std::string& auth_token,
                    bool interactive) {
    std::cerr << "Connecting to " << host << ":" << port << "..." << std::endl;
    xsql::socket::Client client;
    if (!auth_token.empty()) {
        client.set_auth_token(auth_token);
    }
    if (!client.connect(host, port)) {
        std::cerr << "Error: " << client.error() << std::endl;
        return 1;
    }
    std::cerr << "Connected." << std::endl;

    int result = 0;

    if (!query.empty()) {
        // Single query
        auto qr = client.query(query);
        if (qr.success) {
            print_remote_result(qr);
        } else {
            std::cerr << "Error: " << qr.error << "\n";
            result = 1;
        }
    } else if (interactive) {
        // Interactive REPL (remote)
        std::string line;
        std::string stmt;
        std::cout << "PDBSQL Remote Interactive Mode (" << host << ":" << port << ")\n"
                  << "Type .quit to exit\n\n";

        while (true) {
            std::cout << (stmt.empty() ? "pdbsql> " : "   ...> ");
            std::cout.flush();
            if (!std::getline(std::cin, line)) break;
            if (line.empty()) continue;

            if (stmt.empty() && line[0] == '.') {
                if (line == ".quit" || line == ".exit") break;
                if (line == ".tables") {
                    auto qr = client.query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
                    if (qr.success) {
                        std::cout << "Tables:\n";
                        for (const auto& row : qr.rows) {
                            std::cout << "  " << row[0] << "\n";
                        }
                    }
                    continue;
                }
                if (line == ".help") {
                    std::cout << R"(
Commands:
  .tables             List all tables
  .quit / .exit       Exit interactive mode
  .help               Show this help

SQL queries end with semicolon (;)
)" << std::endl;
                    continue;
                }
                std::cerr << "Unknown command: " << line << "\n";
                continue;
            }

            stmt += line + " ";
            size_t last = line.length() - 1;
            while (last > 0 && (line[last] == ' ' || line[last] == '\t')) last--;
            if (line[last] == ';') {
                auto qr = client.query(stmt);
                if (qr.success) {
                    print_remote_result(qr);
                } else {
                    std::cerr << "Error: " << qr.error << "\n";
                }
                stmt.clear();
            }
        }
    }

    return result;
}
