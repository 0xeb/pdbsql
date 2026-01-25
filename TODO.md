# TODO

- [ ] Harden server mode: default to requiring an auth token and document TLS/loopback expectations; plaintext sockets are currently unauthenticated by default.
- [ ] Clarify AI agent data handling: make external provider use explicit/opt-in, add redaction or logging guidance for sensitive PDB content.
- [ ] Double-check server threading: dispatcher now funnels all queries through one COM-initialized worker, but confirm `xsql::socket::Server` doesn’t spawn work that bypasses the handler path (or add an explicit single-thread option if available).
