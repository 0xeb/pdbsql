# pdbsql

Query Windows PDB files with SQL.

```
$ pdbsql ntdll.pdb "SELECT name, rva FROM functions WHERE name LIKE '%Rtl%Heap%' ORDER BY rva"
+---------------------------+----------+
| name                      | rva      |
+---------------------------+----------+
| RtlCreateHeap             | 0x1A240  |
| RtlDestroyHeap            | 0x1B890  |
| RtlAllocateHeap           | 0x1C100  |
| RtlFreeHeap               | 0x1D420  |
+---------------------------+----------+
```

## Why SQL for PDBs?

PDB files are databases. Why not query them like one?

- **Filter**: `WHERE length > 1000 AND name NOT LIKE '%@%'`
- **Sort**: `ORDER BY rva DESC`
- **Aggregate**: `SELECT compiland, COUNT(*) FROM functions GROUP BY compiland`
- **Join**: Cross-reference functions with their source files and line numbers
- **Script**: Pipe results to other tools, generate reports, automate analysis

No SDK. No scripting runtime. Just SQL.

## Tables

| Table | What's in it |
|-------|--------------|
| `functions` | All functions with name, RVA, size, signature |
| `symbol_at(addr)` | TVF: innermost symbol *containing* an address (fast addr→symbol) |
| `publics` | Public symbols (exports, decorated names) |
| `udts` | Structs, classes, unions with size and member count |
| `udt_members` | Fields: offset, type, bit position |
| `enums` | Enumerations |
| `enum_values` | Enum members with values |
| `typedefs` | Type aliases |
| `data` | Global/static variables |
| `sections` | PE sections (.text, .data, .rdata) |
| `compilands` | Object files / translation units |
| `source_files` | Source file paths |
| `line_numbers` | Address-to-source mappings |
| `locals` | Local variables (per function) |
| `parameters` | Function parameters |

## Quick Start

```bash
# Clone with submodules
git clone --recursive https://github.com/0xeb/pdbsql.git
cd pdbsql

# Build (requires Windows + Visual Studio with DIA SDK)
cmake -B build
cmake --build build --config Release

# Run
build\bin\Release\pdbsql.exe your_file.pdb -i
```

## Usage

**One-shot query:**
```bash
pdbsql test.pdb "SELECT name FROM functions WHERE length > 500"
```

**Machine-readable output / bulk export:**
```bash
# TSV/CSV to stdout (the banner goes to stderr, so pipes stay clean)
pdbsql test.pdb -q "SELECT name,rva,length FROM functions LIMIT 100" --format tsv

# One-shot bulk export to disk (no HTTP, no padded table, column-aware).
# --format tsv|csv|jsonl; pick explicit columns for the fast path (no demangle).
pdbsql test.pdb -q "SELECT name,rva,length FROM functions" --format jsonl -o funcs.jsonl --query-timeout 0 --quiet
# --dump <table> is sugar for "SELECT * FROM <table>" (handy, but for functions it
# pulls the expensive undecorated column, so prefer explicit columns for a fast pull).
pdbsql test.pdb --dump sections --format csv -o sections.csv --quiet
```
`WHERE rva = <addr>` and `WHERE name = '<exact>'` are indexed lookups (fast addr→name);
only substring `name LIKE '%…%'` is a full walk. Selecting `undecorated` (the demangled
name) is the one expensive column — omit it for a fast bulk pull.

**Interactive mode:**
```bash
pdbsql test.pdb -i
pdbsql> SELECT name, rva FROM udts WHERE name LIKE '%Manager%';
pdbsql> .schema functions
pdbsql> .quit
```

**HTTP server mode** (expose PDB over HTTP):
```bash
# Terminal 1: Start server
pdbsql test.pdb --http 8080 --token secret123

# Terminal 2: Query over HTTP
curl -X POST http://localhost:8080/query -H "Authorization: Bearer secret123" -d "SELECT * FROM sections"

# Stream a large result row-by-row (chunked, flat memory, early first byte).
# Use curl -N so the client does not buffer the whole response.
curl -N -X POST http://localhost:8080/query -H "X-XSQL-Stream: 1" -d "SELECT name FROM publics"

# Bound a single request (ms; 0 = no limit), independent of the server default
curl -X POST http://localhost:8080/query -H "X-XSQL-Timeout: 5000" -d "SELECT name,rva FROM functions"

# NDJSON stream: one JSON object per row per line (append rows to a file as they arrive)
curl -N -X POST http://localhost:8080/query -H "X-XSQL-Stream: ndjson" -d "SELECT name,rva FROM functions"
```

**Streaming: verified, and its actual tradeoff.** Measured with `curl -N -w
"%{time_starttransfer} %{time_total}"` on a large (multi-gigabyte, million-symbol)
PDB: streamed NDJSON delivers the **first byte in a few milliseconds**, regardless of
result size (vs the buffered response, which only replies once the whole query
finishes) — the low-memory, early-first-byte guarantee holds. But **total wall-clock
to receive everything was noticeably higher streamed than buffered** in that same
test — chunked per-row delivery has real per-write overhead a single buffered
response doesn't pay. Use streaming when you want to start processing rows
immediately or keep server/client memory flat on a huge pull; use the plain buffered
response when the result comfortably fits in memory and you just want it as fast as
possible. `curl -s` (without `-N`) will report the buffered response's timing even
with `X-XSQL-Stream` set, because `curl` itself buffers output without `-N` — always
use `-N` to observe real streaming behavior client-side.

**Bounded address-range queries** (`WHERE rva > X AND rva < Y` on `functions`/
`publics`) are index-backed but not O(1): cost depends on *where* the window lands,
not its width or row count — most windows resolve in single-digit milliseconds, but
one landing in an unlucky address region can take 10+ seconds (measured: a
0x10000-byte window returning ~1,800 rows took ~14s in one region vs ~8ms for a
similar window elsewhere), and it does not warm up on repeat. `X-XSQL-Timeout` and
`POST /cancel` cannot bound or abort a stalled range query — the entire cost is paid
inside a single call before the first row is emitted, so there's no row boundary to
interrupt at; a stall's only recovery is restarting the server. Use range queries for
a known address window, not as a general-purpose scan.

```bash
# Cancel the in-flight query from another connection (it returns its partial rows)
curl -X POST http://localhost:8080/cancel -H "Authorization: Bearer secret123"

# Change the per-query timeout at runtime (default 60000 ms; 0 = no limit)
curl -X POST http://localhost:8080/query -d "UPDATE runtime_settings SET value='30000' WHERE key='query_timeout_ms'"

# ...or seed it at startup (--query-timeout 0 disables the cap for a known-big dump)
pdbsql test.pdb --http 8080 --query-timeout 30
```
> **Note:** `--token` guards the HTTP API only; the MCP endpoint (`--mcp`) is unauthenticated.
>
> The HTTP and MCP servers honor `runtime_settings.query_timeout_ms` (default 60 s)
> per query — `SELECT/UPDATE runtime_settings` to inspect or change it. `--query-timeout`
> is a convenience that seeds the same setting at launch. `/status` is a cheap liveness
> check that never enumerates symbols, so it stays instant on very large PDBs.

**MCP server mode** (Model Context Protocol, for MCP clients):
```bash
# Random port 9000-9999, or pass an explicit port
pdbsql test.pdb --mcp
pdbsql test.pdb --mcp 9123
```
The MCP server exposes a single tool, `pdbsql_query`, that runs SQL directly against the PDB.

## Using pdbsql with an AI agent

pdbsql is a plain SQL CLI — it does **not** embed or run its own AI agent. To let an
external agent or LLM (Claude, Copilot, or any assistant) drive pdbsql, point it at the
tool two ways:

- **As a system prompt:** feed [`prompts/pdbsql_agent.md`](prompts/pdbsql_agent.md) to
  your model as its system/instruction prompt. It documents the full SQL schema, every
  table and column, and worked query patterns, so the model can translate
  natural-language questions into pdbsql SQL and run them via `-q` / `--http` / `--mcp`.
- **Over MCP:** start `pdbsql file.pdb --mcp` and connect any MCP client (see MCP server
  mode above). The client's own model does the reasoning; pdbsql exposes the
  `pdbsql_query` tool that executes SQL against the PDB.

## Real-World Examples

**Triage a crash dump:**
```sql
-- Symbol at the crash address — O(1) containment lookup (any kind), not a full scan
SELECT name, kind, rva, length FROM symbol_at(0x12345);
```

**Understand binary structure:**
```sql
-- Largest functions (complexity indicators)
SELECT name, length FROM functions ORDER BY length DESC LIMIT 20;

-- Executable sections with their names, sizes and flags
SELECT number, name, rva, length, characteristics, readable, writable, executable FROM sections;
```

**Reverse engineering prep:**
```sql
-- Find source files contributing to a given compiland
SELECT sf.filename, c.name AS compiland
FROM source_files sf
JOIN line_numbers ln ON ln.file_id = sf.id
JOIN compilands c ON c.id = ln.compiland_id
WHERE sf.filename LIKE '%crypto%'
GROUP BY sf.filename, c.name;

-- Virtual function tables (C++ RE)
SELECT u.name, COUNT(m.id) as vtable_size
FROM udts u
JOIN udt_members m ON u.id = m.udt_id
WHERE m.name LIKE '%vftable%'
GROUP BY u.name;
```

**Diffing binaries:**
```sql
-- Export function signatures for comparison
SELECT name, length, printf('0x%X', rva) as addr
FROM functions
ORDER BY name;
-- Save to file, diff against another version
```

## Building

**Requirements:**
- Windows (DIA SDK is Windows-only)
- Visual Studio 2019+ with C++ workload (includes DIA SDK)
- CMake 3.20+

**Steps:**
```bash
git clone --recursive https://github.com/0xeb/pdbsql.git
cd pdbsql

# Initialize submodules (libxsql)
git submodule update --init --recursive

cmake -B build
cmake --build build --config Release

```

**Build options:**
- `PDBSQL_WITH_HTTP=ON` (default): HTTP REST server
- `PDBSQL_WITH_MCP=ON` (default): MCP server (SSE), fetches fastmcpp

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified pdbsql, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use pdbsql as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by pdbsql in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [0xeb/pdbsql/issues](https://github.com/0xeb/pdbsql/issues).

If pdbsql materially informs a distributed project, preserve the human origin: credit pdbsql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, the Windows Debug Interface Access (DIA) SDK, and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).

Releases up to v0.0.3 remain under the MPL-2.0 they were published with; v0.0.4 and all subsequent releases are under the Human-Origin Source License v1.0.

## The xsql family

pdbsql is part of a family of tools that expose different binary-analysis and
debug-information platforms through the **same** SQL surface, all built on the
shared [libxsql](https://github.com/0xeb/libxsql) virtual-table framework. A
query you learn against one tool largely carries over to the others.

**Reverse-engineering platforms**
- **[idasql](https://github.com/allthingsida/idasql)** — IDA Pro databases as SQL.
- **[bnsql](https://github.com/0xeb/bnsql)** — Binary Ninja databases as SQL.
- **[ghidrasql](https://github.com/0xeb/ghidrasql)** — Ghidra databases as SQL.

**Debug info & compiler data**
- **[dwarfsql](https://github.com/0xeb/dwarfsql)** — DWARF debug information as SQL.
- **[clangsql](https://github.com/0xeb/clangsql)** — Clang AST as SQL.

**Core**
- **[libxsql](https://github.com/0xeb/libxsql)** — the C++ SQLite virtual-table
  framework every tool above is built on.
