# pdbsql

Query Windows PDB files with SQL. Ask questions in plain English.

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

Or just ask:

```
$ pdbsql ntdll.pdb --prompt "Find heap-related functions"
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

**Interactive mode:**
```bash
pdbsql test.pdb -i
pdbsql> SELECT name, rva FROM udts WHERE name LIKE '%Manager%';
pdbsql> .schema functions
pdbsql> .quit
```

**Server mode** (expose PDB over network):
```bash
# Terminal 1: Start server
pdbsql test.pdb --server 13337 --token secret123

# Terminal 2: Query remotely
pdbsql --remote localhost:13337 --token secret123 -q "SELECT * FROM sections"
```

## AI Agent Mode

Don't know SQL? Don't know the schema? Just ask.

```bash
pdbsql kernel32.pdb --prompt "Which functions reference the string 'LoadLibrary'?"
pdbsql ntdll.pdb --prompt "Show me the largest 10 C++ classes with their member counts"
pdbsql myapp.pdb --prompt "Find all virtual functions in classes that inherit from IUnknown"
```

**Interactive with AI:**
```bash
pdbsql test.pdb -i --agent

pdbsql> what tables are available?
pdbsql> find functions that look like constructors
pdbsql> show me structs larger than 4KB
pdbsql> which source files have the most functions?
```

The agent translates your questions to SQL, runs the query, and explains results. SQL passthrough still works - if you type `SELECT ...`, it executes directly.

### Prerequisites for AI Features

The AI agent requires one of these CLI tools installed and authenticated:

| Provider | CLI Tool | Install | Login |
|----------|----------|---------|-------|
| Claude (default) | [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm install -g @anthropic-ai/claude-code` | Run `claude`, then `/login` |
| GitHub Copilot | [Copilot CLI](https://github.com/features/copilot/cli/) | `npm install -g @github/copilot` | Run `copilot`, then `/login` |

**Important:** You must be logged in before using AI features.

### Agent Setup

The agent uses [libagents](https://github.com/0xeb/libagents) to connect to LLM providers. Configure once:

```bash
pdbsql test.pdb -i
pdbsql> .agent provider copilot
pdbsql> .agent byok enable
pdbsql> .agent byok key YOUR_API_KEY
pdbsql> .agent byok endpoint https://api.openai.com/v1
pdbsql> .agent byok model gpt-4
pdbsql> .agent byok type openai
```

Settings persist to `%APPDATA%\pdbsql\agent_settings.json`.

Supported providers: `copilot`, `claude`
BYOK types: `openai`, `anthropic`, `azure`

## Real-World Examples

**Triage a crash dump:**
```sql
-- Find function at crash address
SELECT name, rva, rva + length as end_rva
FROM functions
WHERE rva <= 0x12345 AND rva + length > 0x12345;
```

**Understand binary structure:**
```sql
-- Largest functions (complexity indicators)
SELECT name, length FROM functions ORDER BY length DESC LIMIT 20;

-- Code vs data ratio per section
SELECT name, virtual_size, characteristics FROM sections;
```

**Reverse engineering prep:**
```sql
-- Find interesting string references
SELECT f.name, f.rva FROM functions f
JOIN line_numbers ln ON f.id = ln.function_id
WHERE ln.source_file LIKE '%crypto%';

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

## For AI Agents (MCP/Tool Use)

pdbsql exposes a single tool: `pdbsql(query: string) -> string`

The tool accepts SQL queries and returns formatted results. AI agents can:

1. Explore schema with `.tables` and `.schema <table>`
2. Run queries and iterate based on results
3. Combine multiple queries to answer complex questions

**System prompt snippet for your agent:**
```
You have access to a PDB file via the pdbsql tool. Available tables:
functions, publics, udts, udt_members, enums, enum_values, typedefs,
data, sections, compilands, source_files, line_numbers, locals, parameters.

Use SQL to explore. Start with schema discovery, then targeted queries.
```

The embedded agent prompt includes full schema documentation - just enable `--agent` and it handles the rest.

## Building

**Requirements:**
- Windows (DIA SDK is Windows-only)
- Visual Studio 2019+ with C++ workload (includes DIA SDK)
- CMake 3.20+

**Steps:**
```bash
git clone --recursive https://github.com/0xeb/pdbsql.git
cd pdbsql

# Initialize nested submodules (for AI agent support)
git submodule update --init --recursive

cmake -B build
cmake --build build --config Release

```

**Build options:**
- `PDBSQL_WITH_AI_AGENT=ON` (default): Enable AI agent support

## Privacy Note

When using AI agent mode, your prompts and query results are sent to the configured LLM provider. Don't use this with sensitive symbols unless you're comfortable with that data leaving your machine. Local SQL mode (`-i` without `--agent`) processes everything locally.

## License

MIT

## See Also

- [libxsql](https://github.com/0xeb/libxsql) - SQLite virtual table framework (powers pdbsql)
- [libagents](https://github.com/0xeb/libagents) - Unified C++ agent library (Copilot/Claude)
- [idasql](https://github.com/0xeb/idasql) - SQL interface for IDA Pro databases
