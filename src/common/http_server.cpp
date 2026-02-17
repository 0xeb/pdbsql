#include "http_server.hpp"

#ifdef PDBSQL_HAS_HTTP

namespace pdbsql {

static const char* HTTP_HELP_TEXT = R"(PDBSQL HTTP REST API
====================

SQL interface for Windows PDB debug symbols via HTTP.

Endpoints:
  GET  /         - Welcome message
  GET  /help     - This documentation
  POST /query    - Execute SQL (body = raw SQL, response = JSON)
  GET  /status   - Server health check
  POST /shutdown - Stop server

Tables:
  functions       - Functions with RVA, size, section info
  publics         - Public symbols
  data            - Data symbols (global/static variables)
  udts            - User-defined types (classes, structs, unions)
  enums           - Enumerations
  typedefs        - Type definitions
  thunks          - Thunk symbols
  labels          - Labels
  compilands      - Compilation units
  source_files    - Source file paths
  line_numbers    - Line number mappings
  sections        - PE sections
  udt_members     - UDT member fields
  enum_values     - Enumeration values
  base_classes    - Class inheritance
  locals          - Local variables
  parameters      - Function parameters

Response Format:
  Success: {"success": true, "columns": [...], "rows": [[...]], "row_count": N}
  Error:   {"success": false, "error": "message"}

Example:
  curl http://localhost:<port>/help
  curl -X POST http://localhost:<port>/query -d "SELECT name FROM functions LIMIT 5"
)";

int PdbsqlHTTPServer::start(int port, HTTPQueryCallback query_cb,
                             const std::string& bind_addr, bool use_queue) {
    if (impl_ && impl_->is_running()) {
        return impl_->port();
    }

    xsql::thinclient::http_query_server_config config;
    config.tool_name = "pdbsql";
    config.help_text = HTTP_HELP_TEXT;
    config.port = port;
    config.bind_address = bind_addr;
    config.query_fn = std::move(query_cb);
    config.use_queue = use_queue;
    config.status_fn = []() {
        return xsql::json{{"mode", "repl"}};
    };

    impl_ = std::make_unique<xsql::thinclient::http_query_server>(config);
    return impl_->start();
}

void PdbsqlHTTPServer::run_until_stopped() {
    if (impl_) impl_->run_until_stopped();
}

void PdbsqlHTTPServer::stop() {
    if (impl_) {
        impl_->stop();
        impl_.reset();
    }
}

void PdbsqlHTTPServer::set_interrupt_check(std::function<bool()> check) {
    if (impl_) impl_->set_interrupt_check(std::move(check));
}

std::string format_http_info(int port) {
    return xsql::thinclient::format_http_info("pdbsql", port);
}

std::string format_http_status(int port, bool running) {
    return xsql::thinclient::format_http_status(port, running);
}

} // namespace pdbsql

#endif // PDBSQL_HAS_HTTP
