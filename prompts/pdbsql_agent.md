# PDBSQL Agent Guide

A comprehensive reference for AI agents to effectively use PDBSQL - an SQL interface for analyzing Windows PDB (Program Database) debug symbol files.

---

## What are PDB Files and Why SQL?

**PDB (Program Database)** files are Microsoft's debug symbol format containing:
- **Function symbols** - Names, addresses (RVAs), and sizes
- **Type information** - Structs, classes, unions, enums, typedefs
- **Source line mapping** - Line numbers to code addresses
- **Compilands** - Object files and compilation units
- **Public symbols** - Exported symbols
- **Local variables** - Per-function local variable information

**PDBSQL** exposes all this debug information through SQL virtual tables, enabling:
- Complex queries across multiple symbol types (JOINs)
- Aggregations and statistics (COUNT, GROUP BY)
- Pattern detection across the entire symbol database
- Scriptable analysis without writing custom PDB parsers

---

## Core Concepts for PDB Analysis

### Addresses (RVA)
Everything in a PDB has a **Relative Virtual Address (RVA)** - an offset from the image base where code or data lives. RVAs are unsigned 32-bit integers in SQL. Use `printf('0x%X', rva)` for hex display.

### Functions
Functions are code symbols with:
- `name` - Function name (decorated or undecorated)
- `rva` - Relative virtual address
- `length` - Size in bytes
- `section` - PE section number
- `offset` - Section offset

### UDTs (User-Defined Types)
**UDTs** are structs, classes, and unions:
- `name` - Type name
- `size` - Size in bytes
- Data members via `udt_fields`; member functions via `udt_methods`
- Base classes via `base_classes` (walk hierarchies **upward** — see that table)
- `udts` / `enums` are **deduplicated**: one row per distinct type. The raw
  per-compiland records live in `udt_records` / `enum_records`

### Compilands
**Compilands** represent object files (`.obj`) that were linked:
- `name` - Object file name
- `library` - Static library if applicable
- `language` - Source language code (NULL when the compiland records none)

### Source Files and Line Numbers
PDB files map source code to addresses:
- `source_files` - Original source file paths
- `line_numbers` - Line number to RVA mapping

---

## Tables Reference

### Symbol Tables (Read-Only)

#### functions
All function symbols in the PDB.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Symbol ID |
| `name` | TEXT | Function name (decorated) |
| `undecorated` | TEXT | Undecorated name |
| `rva` | INT | Relative virtual address |
| `length` | INT | Function size in bytes |
| `section` | INT | PE section number |
| `offset` | INT | Section offset |

```sql
-- 10 largest functions
SELECT name, length FROM functions ORDER BY length DESC LIMIT 10;

-- Functions in .text section (usually section 1)
SELECT name, printf('0x%X', rva) as addr FROM functions WHERE section = 1;

-- Find main/WinMain
SELECT * FROM functions WHERE undecorated LIKE '%main%';
```

#### symbol_at(addr) — table-valued function
The innermost symbol of **any** kind **containing** an address (via DIA `findSymbolByRVA`,
O(1)). Pass the address as `symbol_at(<addr>)` or `WHERE addr = <addr>`; returns 0 or 1
row. This is the fast addr→symbol primitive for symbolization — unlike `functions WHERE
rva = X` (exact start only), it resolves any address a symbol spans. See "Indexed lookups".

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT | HIDDEN input — the query address (bound by `symbol_at(<addr>)`) |
| `id` | INT | Symbol ID |
| `name` | TEXT | Symbol name (decorated) |
| `undecorated` | TEXT | Undecorated name |
| `kind` | TEXT | SymTag: `Function`, `PublicSymbol`, `Data`, `Label`, … |
| `rva` | INT | Matched symbol's start RVA (may be ≤ `addr`) |
| `length` | INT | Matched symbol's size in bytes |
| `section` | INT | PE section number |
| `offset` | INT | Section offset |

```sql
-- What symbol is at this address (even mid-function)?
SELECT name, kind, rva, length FROM symbol_at(0x14002A1F0);
```

#### publics
Public symbols (exports, etc.).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Symbol ID |
| `name` | TEXT | Symbol name |
| `undecorated` | TEXT | Undecorated name |
| `rva` | INT | Relative virtual address |
| `length` | INT | Symbol size in bytes |
| `section` | INT | PE section number |
| `offset` | INT | Section offset |

```sql
-- List all exported symbols
SELECT name FROM publics ORDER BY name;
```

#### data
Global and static data symbols.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Symbol ID |
| `name` | TEXT | Data symbol name |
| `rva` | INT | Relative virtual address |
| `length` | INT | Data size in bytes |
| `section` | INT | PE section number |
| `offset` | INT | Section offset |

```sql
-- Find global variables
SELECT name, printf('0x%X', rva) as addr FROM data;
```

#### udts
User-defined types (structs, classes, unions).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Type ID |
| `name` | TEXT | Type name |
| `length` | INT | Size in bytes |

> **`udts` gives you one row per distinct type.** DIA emits a type record per
> *compiland that defines the type*, so the underlying debug info repeats names
> heavily (1.75M records collapse to ~1.23M distinct names on a large PDB).
> `udts` deduplicates; **`udt_records`** exposes the raw per-compiland rows for
> the rare questions that need them.
>
> **`name` is NULL for anonymous types.** DIA labels them `<unnamed-tag>` /
> `<anonymous-tag>`, but those are display placeholders, not names: many unrelated
> types share one and they cannot be looked up by name. They are reported as NULL
> and are never merged with each other. Match them with `IS NULL`, never `= '...'`.

```sql
-- Largest structures -- no duplicates
SELECT name, length FROM udts WHERE name IS NOT NULL ORDER BY length DESC LIMIT 10;

-- Which types are compiled into the most translation units? (header bloat)
SELECT name, COUNT(*) AS tus FROM udt_records
WHERE name IS NOT NULL GROUP BY name ORDER BY tus DESC LIMIT 10;

-- Find types by name pattern
SELECT * FROM udts WHERE name LIKE '%Config%';
```

> ⚠️ `SELECT COUNT(*) FROM udts` walks every type record and can exceed the default
> 60 s timeout on a multi-GB PDB. A `LIMIT` stays cheap (deduplication streams), so
> prefer bounded queries; raise `query_timeout_ms` deliberately if you truly need a
> whole-table count.

#### enums
Enumeration types.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Enum type ID |
| `name` | TEXT | Enum name |
| `length` | INT | Underlying type size |

```sql
-- List all enums
SELECT name FROM enums ORDER BY name;
```

#### typedefs
Type aliases.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Typedef ID |
| `name` | TEXT | Typedef name |
| `length` | INT | Underlying type size |

#### thunks
Thunk symbols (import stubs, virtual function thunks).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Thunk ID |
| `name` | TEXT | Thunk name |
| `rva` | INT | Relative virtual address |
| `length` | INT | Thunk size in bytes |
| `section` | INT | PE section number |

#### labels
Code labels (not functions).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Label ID |
| `name` | TEXT | Label name |
| `rva` | INT | Relative virtual address |
| `section` | INT | PE section number |
| `offset` | INT | Section offset |

> **Both are nested tables.** Thunks live under their compiland and labels under
> their function, so a scan of either walks parents rather than the global symbol
> list. `WHERE id = <id>` is indexed; `WHERE name = '<name>'` is **not** — it
> scans, unlike the equivalent on `functions`/`publics`. These tables are small
> (hundreds of rows even on a multi-GB PDB), so a scan is cheap.

### Type Detail Tables

#### udt_fields
Data members of structs/classes/unions.

| Column | Type | Description |
|--------|------|-------------|
| `udt_id` | INT | Parent UDT ID |
| `udt_name` | TEXT | Parent UDT name |
| `id` | INT | Member ID |
| `name` | TEXT | Member name |
| `type` | TEXT | Member type (`int`, `const char*`, `Foo[16]`, …) |
| `offset` | INT | Byte offset within the parent |
| `length` | INT | Member size |
| `access` | TEXT | `private` \| `protected` \| `public` |
| `is_static` | INT | 1 if a static data member |

#### udt_methods
Member functions of structs/classes/unions.

| Column | Type | Description |
|--------|------|-------------|
| `udt_id` | INT | Parent UDT ID |
| `udt_name` | TEXT | Parent UDT name |
| `id` | INT | Member ID |
| `name` | TEXT | Method name |
| `type` | TEXT | Rendered signature, e.g. `double (void)` |
| `length` | INT | Code size, when the record carries one |
| `access` | TEXT | `private` \| `protected` \| `public` |
| `is_static` | INT | 1 if a static member function |
| `is_virtual` | INT | 1 if virtual |
| `is_pure` | INT | 1 if pure virtual (`= 0`) |

> **Fields and methods are separate tables so every column means something on
> every row.** A field always has an offset; a method never does, and only a
> method can be virtual. There is no `kind` discriminator and no
> NULL-half-the-time `offset`.
>
> For "all members of X", `UNION ALL` them explicitly:
>
> ```sql
> SELECT name, type, 'field'  AS kind FROM udt_fields  WHERE udt_name = 'MyClass'
> UNION ALL
> SELECT name, type, 'method' AS kind FROM udt_methods WHERE udt_name = 'MyClass';
> ```
>
> Methods typically outnumber fields ~7:1 on a large C++ PDB, so don't reach for
> the union unless you actually want both.
>
> For virtual **inheritance** (not virtual methods), use `base_classes.is_virtual`.

```sql
-- Memory layout of a struct
SELECT name, offset, length, type
FROM udt_fields
WHERE udt_name = 'MyStruct'
ORDER BY offset;

-- The virtual interface of a class
SELECT name, type, is_pure
FROM udt_methods
WHERE udt_name = 'MyClass' AND is_virtual = 1;

-- Abstract classes (have at least one pure virtual)
SELECT DISTINCT udt_name FROM udt_methods WHERE is_pure = 1;

-- Public API surface of a class
SELECT name, type FROM udt_methods
WHERE udt_name = 'MyClass' AND access = 'public';

-- Find all pointer fields
SELECT udt_name, name FROM udt_fields WHERE type LIKE '%*%';
```

#### enum_values
Enumeration constant values.

| Column | Type | Description |
|--------|------|-------------|
| `enum_id` | INT | Parent enum ID |
| `enum_name` | TEXT | Parent enum name |
| `id` | INT | Value entry ID |
| `name` | TEXT | Constant name |
| `value` | INT | Constant value |

```sql
-- Values in an enum
SELECT name, value FROM enum_values WHERE enum_name = 'ErrorCode' ORDER BY value;
```

#### base_classes
Base class relationships (C++ inheritance).

| Column | Type | Description |
|--------|------|-------------|
| `derived_id` | INT | Derived class ID |
| `derived_name` | TEXT | Derived class name |
| `base_id` | INT | Base class ID |
| `base_name` | TEXT | Base class name |
| `offset` | INT | Base class offset |
| `is_virtual` | INT | 1 if virtual inheritance |
| `access` | INT | Access modifier (DIA enum: 1=private, 2=protected, 3=public) |

> **Walk hierarchies UPWARD (derived → base). This is a hard rule, not a tuning tip.**
>
> DIA records what a class *derives from* and offers **no reverse lookup**, so only
> the child→parent direction can be indexed:
>
> | Predicate | Cost |
> |---|---|
> | `WHERE derived_id = <id>` | indexed — instant |
> | `WHERE derived_name = '<name>'` | indexed — instant |
> | `WHERE base_name = '<name>'` | **full table scan** |
> | `WHERE base_id = <id>` | **full table scan** |
>
> A recursive CTE that walks *downward* (`base_name` → subclasses) re-scans the
> whole table at **every** recursion step. On a large PDB one such scan costs
> minutes, so a downward walk is effectively unusable. Seed from the derived class
> and traverse toward its bases.

```sql
-- Ancestors of a class (indexed at every step)
WITH RECURSIVE ancestors(derived, base, depth) AS (
  SELECT derived_name, base_name, 1
  FROM base_classes
  WHERE derived_name = 'MyClass'

  UNION ALL

  SELECT bc.derived_name, bc.base_name, a.depth + 1
  FROM base_classes bc
  JOIN ancestors a ON bc.derived_name = a.base      -- upward: derived_name is indexed
  WHERE a.depth < 8
)
SELECT DISTINCT base, depth FROM ancestors ORDER BY depth;

-- Direct bases of one class
SELECT base_name, offset, is_virtual, access
FROM base_classes WHERE derived_name = 'MyClass';

-- Find all derived classes of a base -- SCANS the table. Fine as a ONE-OFF query;
-- never put this shape inside a recursive CTE or a per-row join.
SELECT derived_name FROM base_classes WHERE base_name = 'IUnknown';
```

### Compilation Unit Tables

#### compilands
Object files (compilation units).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Compiland ID |
| `name` | TEXT | Object file name |
| `library` | TEXT | Static library name |
| `language` | INT | Language code |

```sql
-- List all object files
SELECT name, library FROM compilands ORDER BY name;

-- Count object files per library
SELECT library, COUNT(*) as obj_count
FROM compilands
GROUP BY library
ORDER BY obj_count DESC;
```

#### source_files
Source file paths referenced in debug info.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | File ID |
| `filename` | TEXT | Source file path |
| `checksum_type` | INT | Checksum algorithm |

```sql
-- List all source files
SELECT filename FROM source_files ORDER BY filename;

-- Find header files
SELECT filename FROM source_files WHERE filename LIKE '%.h' OR filename LIKE '%.hpp';
```

#### line_numbers
Source line to address mapping.

| Column | Type | Description |
|--------|------|-------------|
| `file_id` | INT | Source file ID |
| `line` | INT | Line number |
| `column` | INT | Column number |
| `rva` | INT | Code address |
| `length` | INT | Code length |
| `compiland_id` | INT | Compiland ID |

```sql
-- Lines in a specific file
SELECT line, printf('0x%X', rva) as addr
FROM line_numbers ln
JOIN source_files sf ON ln.file_id = sf.id
WHERE sf.filename LIKE '%main.cpp'
ORDER BY line;

-- Find code density (lines per RVA)
SELECT COUNT(DISTINCT line) as line_count, COUNT(DISTINCT rva) as addr_count
FROM line_numbers;
```

### PE Section Tables

#### sections
PE sections, read from the image's **section headers** — so they resolve even for
PDBs that expose no section *contributions* (where this table used to return 0 rows).
Each row is a real named section (`.text`, `.rdata`, `.data`, …).

| Column | Type | Description |
|--------|------|-------------|
| `number` | INT | Section number (1-based) |
| `name` | TEXT | Section name (`.text`, `.data`, `.rdata`, …) |
| `rva` | INT | Section RVA |
| `length` | INT | Section size |
| `characteristics` | INT | Section flags (IMAGE_SCN_*, unsigned) |
| `readable` | INT | 1 if readable |
| `writable` | INT | 1 if writable |
| `executable` | INT | 1 if executable |
| `code` | INT | 1 if code section |

```sql
-- All sections with names and attributes
SELECT number, name, printf('0x%X', rva) AS addr, length, executable, writable
FROM sections ORDER BY number;

-- Code sections
SELECT number, name, printf('0x%X', rva) AS addr, length
FROM sections WHERE executable = 1;
```

### Function-Scoped Tables

**IMPORTANT:** These tables require filtering by function ID for performance.

#### locals
Local variables within functions.

| Column | Type | Description |
|--------|------|-------------|
| `func_id` | INT | Parent function ID |
| `func_name` | TEXT | Parent function name |
| `id` | INT | Variable ID |
| `name` | TEXT | Variable name |
| `type` | TEXT | Variable type |
| `location` | TEXT | `static` \| `regrel` \| `thisrel` \| `register` \| `tls` \| … |
| `frame_offset` | INT | Frame-relative offset, **NULL** when not frame-relative |
| `register` | INT | Register number, **NULL** when not register-based |

```sql
-- SLOW: Scans all functions
SELECT * FROM locals;

-- FAST: Filter by func_id
SELECT name, type FROM locals WHERE func_id = 12345;

-- Join with functions
SELECT f.name, l.name as var_name, l.type
FROM functions f
JOIN locals l ON f.id = l.func_id
WHERE f.name = 'main';
```

#### parameters
Function parameters.

| Column | Type | Description |
|--------|------|-------------|
| `func_id` | INT | Parent function ID |
| `func_name` | TEXT | Parent function name |
| `id` | INT | Parameter ID |
| `name` | TEXT | Parameter name |
| `type` | TEXT | Parameter type |
| `ordinal` | INT | 0-based position in the signature — **`ORDER BY ordinal`** |
| `location` | TEXT | `static` \| `regrel` \| `thisrel` \| `register` \| … |
| `frame_offset` | INT | Frame-relative offset, **NULL** when not frame-relative |
| `register` | INT | Register number, **NULL** when not register-based |

```sql
-- Parameters of a specific function
SELECT name, type
FROM parameters
WHERE func_name = 'MyFunction';
```

### runtime_settings (writable — session control)

A small **writable** table of runtime knobs. The one that matters for querying is
**`query_timeout_ms`** — see *Performance & Fast Paths* below.

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT | Setting name (e.g. `query_timeout_ms`) |
| `value` | TEXT | Current value |
| `type` | TEXT | `int` / `bool` |
| `scope` | TEXT | `common` / `action` |

```sql
-- Read the current query timeout (milliseconds; default 60000)
SELECT value FROM runtime_settings WHERE key = 'query_timeout_ms';

-- Raise it to 5 minutes for a heavy query (0 = no limit)
UPDATE runtime_settings SET value = 300000 WHERE key = 'query_timeout_ms';
```

(The CLI flag `--query-timeout <seconds>` seeds this before a server starts.)

---

## Common Query Patterns

### Find Functions by Name Pattern

```sql
-- Case-insensitive search
SELECT name, rva, length FROM functions WHERE name LIKE '%Init%';

-- Undecorated search (C++ name mangling removed)
SELECT undecorated, rva FROM functions WHERE undecorated LIKE '%vector%';
```

### Type Information Analysis

```sql
-- Find all structs with a specific member
SELECT DISTINCT udt_name
FROM udt_fields
WHERE name = 'dwSize';

-- Struct size distribution
SELECT
  CASE
    WHEN length < 16 THEN 'tiny (<16)'
    WHEN length < 64 THEN 'small (16-64)'
    WHEN length < 256 THEN 'medium (64-256)'
    WHEN length < 1024 THEN 'large (256-1K)'
    ELSE 'huge (>1K)'
  END as category,
  COUNT(*) as count
FROM udts
GROUP BY category
ORDER BY
  CASE category
    WHEN 'tiny (<16)' THEN 1
    WHEN 'small (16-64)' THEN 2
    WHEN 'medium (64-256)' THEN 3
    WHEN 'large (256-1K)' THEN 4
    ELSE 5
  END;
```

### Source Code Analysis

```sql
-- Functions by source file
SELECT sf.filename, COUNT(*) as func_count
FROM functions f
JOIN line_numbers ln ON f.rva = ln.rva
JOIN source_files sf ON ln.file_id = sf.id
GROUP BY sf.filename
ORDER BY func_count DESC;

-- Code coverage per file (RVA ranges)
SELECT
  sf.filename,
  COUNT(DISTINCT ln.rva) as unique_addresses,
  MIN(ln.line) as first_line,
  MAX(ln.line) as last_line
FROM line_numbers ln
JOIN source_files sf ON ln.file_id = sf.id
GROUP BY sf.filename
ORDER BY unique_addresses DESC;
```

### Compiland Analysis

```sql
-- Object file statistics
SELECT
  c.name as obj_file,
  COUNT(DISTINCT f.id) as function_count,
  SUM(f.length) as total_code_size
FROM compilands c
LEFT JOIN line_numbers ln ON c.id = ln.compiland_id
LEFT JOIN functions f ON ln.rva = f.rva
GROUP BY c.id
ORDER BY total_code_size DESC;
```

### Type Hierarchy

```sql
-- Full ancestor chain of a class, with the depth at which each base appears.
-- Walks UPWARD via derived_name, which is indexed at every step (see base_classes).
WITH RECURSIVE ancestors(derived, base, level) AS (
  SELECT derived_name, base_name, 1
  FROM base_classes WHERE derived_name = 'MyClass'

  UNION ALL

  SELECT bc.derived_name, bc.base_name, a.level + 1
  FROM base_classes bc
  JOIN ancestors a ON bc.derived_name = a.base
  WHERE a.level < 10
)
SELECT DISTINCT base, level FROM ancestors ORDER BY level, base;
```

To go the other way — *"everything implementing `IUnknown`"* — there is no indexed
path (DIA has no reverse lookup), so do it as a **single bounded scan** rather than
a recursive walk:

```sql
-- Direct subclasses only: ONE scan. A recursive version multiplies that scan by
-- every level and is not viable on a large PDB.
SELECT DISTINCT derived_name FROM base_classes WHERE base_name = 'IUnknown';
```

### Section Distribution

```sql
-- Symbol distribution by section
SELECT
  s.number as section,
  COUNT(f.id) as function_count,
  SUM(f.length) as total_size
FROM sections s
LEFT JOIN functions f ON s.number = f.section
GROUP BY s.number
ORDER BY total_size DESC;
```

---

## Performance & Fast Paths

pdbsql reads symbols through Microsoft DIA. A few cost characteristics dominate;
knowing them lets you pick fast queries and avoid the one slow pattern.

### Counting is cheap — enumerating everything is not

- **`SELECT COUNT(*) FROM <table>` is fast.** It asks DIA for the count directly and
  never materializes rows — quick even on tables with hundreds of thousands of rows.
  ```sql
  SELECT COUNT(*) FROM functions;   -- returns in ~a second, even on a huge PDB
  ```
- **A full enumeration with no filter and no LIMIT is inherently slow on large PDBs.**
  `SELECT name FROM functions` (every row) walks every DIA symbol and can take
  *minutes* on a big optimized/shipping PDB — that is DIA's per-symbol cost, not a
  bug. Don't dump a whole large table unless you truly need every row. Prefer:
  ```sql
  SELECT name FROM functions LIMIT 100;                         -- explore
  SELECT name, length FROM udts ORDER BY length DESC LIMIT 20;  -- top-N
  SELECT * FROM functions WHERE undecorated LIKE '%Init%';      -- filter
  SELECT COUNT(*) FROM functions;                               -- just the count
  ```
- Ordinary filtered / `LIMIT` / top-N queries are cheap to plan and start, even on
  the biggest tables.

### Indexed lookups & cheap column subsets (best for symbolization)

- **`WHERE rva = <addr>` on `functions`/`publics` is a direct DIA address-index lookup**
  (findSymbolByRVA) — effectively O(1), not a walk. It is the fast addr→name primitive.
  `WHERE name = '<exact>'` and `WHERE id = <n>` push down too. Only substring
  `name LIKE '%...%'` is an unavoidable full walk.
  ```sql
  SELECT name FROM functions WHERE rva = 73623824;  -- instant (indexed), not a walk
  SELECT rva  FROM functions WHERE name = 'CalcHash';
  ```
- **`WHERE rva > / >= / < / <= <addr>` on `functions`/`publics` is a BOUNDED range**
  lookup (one address-index seek + a forward walk that stops at the upper bound) — use
  it for "what's in this address window", not as a substitute for `LIMIT`/`OFFSET`
  paging of the whole table. For a full-table pull, use a plain unbounded `SELECT`
  with `X-XSQL-Stream` (HTTP) or `--dump`/`--format jsonl` (CLI) instead.
  ```sql
  SELECT name, rva FROM functions WHERE rva > 0x140010000 AND rva < 0x140020000;
  ```
  **Cost is driven by WHERE the window lands, not how wide it is or how many rows
  it returns.** The seek is not O(1): most windows resolve in single-digit
  milliseconds regardless of size, but a window landing in an unlucky address
  region can take 10+ seconds even for a modest window with a normal row count
  (measured: a 0x10000-byte window returning 1,834 rows took ~14s in one region,
  vs ~8ms for a similar-sized/row-count window elsewhere) — and it does NOT warm
  up on repeat, unlike a flat `rva=` lookup. **The effect is size-dependent**: that
  ~14s worst case was on a 3.14 GB / 1.31M-function PDB, while a sweep of eleven
  equal-width windows across a 131 MB / 93k-function PDB found *no* cliff at all
  (every window 3–10 ms). Expect it on multi-GB PDBs; don't design around it on
  small ones. **`X-XSQL-Timeout`/`--query-timeout`/
  `POST /cancel` cannot bound or abort this**: they are all checked between rows,
  but the entire cost is paid inside the single seek call before the first row is
  ever emitted, so there is no row boundary to interrupt at. A stalled range query
  currently has no recovery short of restarting the server (`POST /shutdown` +
  relaunch).
- **`symbol_at(<addr>)` resolves an address INSIDE a symbol → the containing symbol**
  (of any kind), also via findSymbolByRVA — O(1), the true symbolization primitive.
  Unlike `WHERE rva = X` (which needs the exact start), `symbol_at` accepts any address
  the symbol spans and returns 0 or 1 row: `kind` names the SymTag (`Function`,
  `PublicSymbol`, `Data`, …); `rva`/`length` describe the matched symbol (its start may
  be ≤ the queried address); an address in a gap returns no row.
  ```sql
  SELECT name, kind, rva, length FROM symbol_at(0x14002A1F0);  -- symbol at an address
  SELECT name FROM symbol_at(0x14002A1F0) WHERE kind = 'Function';
  -- SELECT * FROM symbol_at WHERE addr = 0x14002A1F0;  -- equivalent explicit form
  ```
- **Select only the columns you need.** `undecorated` (the demangled name) is by far the
  most expensive field. A `SELECT name, rva, length …` pull skips the demangle and is
  dramatically cheaper than one that includes `undecorated`; add `undecorated` only when
  you actually need demangled names.

### Queries are time-bounded (you may get partial results)

The server and CLI abort a query that exceeds `query_timeout_ms` (default **60 s**)
and return the rows gathered so far **plus a "results are partial" warning** — a
runaway query can no longer hang the tool. Tune it per query via `runtime_settings`
(above) or start a server with `--query-timeout <seconds>` (`0` = no limit). If a
result comes back partial, add a `LIMIT`/`WHERE`, or raise the timeout deliberately.
Over HTTP you can bound a single request with the header `X-XSQL-Timeout: <ms>`
(`0` = no limit), independent of the server default. To stop an **already-running**
query, send `POST /cancel` from another connection — the in-flight query returns its
partial rows; a client that drops a streamed connection mid-flight cancels it too.

**Detect this in code, not by string-matching the prose.** A truncated statement
reports `"partial": true` and carries the human-readable text in `warnings[]`:

```json
{ "success": true,
  "results": [ { "success": true, "row_count": 1258, "elapsed_ms": 25,
                 "error": null, "partial": true,
                 "warnings": ["query timed out; returning partial rows"] } ] }
```

Branch on `results[].partial`. Note that `success` stays `true` — partial results
are a success carrying fewer rows, not an error. The one exception is a statement
whose rows only materialize at completion (an unqualified `COUNT(*)`, say): it has
no partial rows to return, so it comes back `success: false` with
`error: "Query timed out"` and `partial: false`.

### Use equality filters and bounded output

```sql
-- FAST: constraint pushdown on a scoped table
SELECT * FROM locals WHERE func_id = 12345;
-- SLOW: full scan by an unindexed text column
SELECT * FROM locals WHERE func_name LIKE '%main%';

-- Exact match fastest; leading-wildcard LIKE slowest
SELECT * FROM udts WHERE name = 'MyStruct';
SELECT * FROM udts WHERE name LIKE 'My%';      -- ok (anchored)
SELECT * FROM udts WHERE name LIKE '%Struct%'; -- slowest (leading wildcard)
```

Always filter function-scoped tables (`locals`, `parameters`) by `func_id`.

### Large results: stream over HTTP, or export from the CLI

Over HTTP, add `X-XSQL-Stream: 1` to `POST /query` to stream the result row-by-row
(chunked): peak memory stays ~one row and the first bytes arrive immediately — use a
client that does NOT buffer the whole response (e.g. `curl -N`). The wire format is the
same JSON envelope, emitted incrementally. Use `X-XSQL-Stream: ndjson` instead for
newline-delimited JSON — one self-describing object per row per line, ideal for a client
that appends rows to a file as they arrive.

For a one-time **bulk export**, the CLI is simplest: it writes straight to disk with no
HTTP framing, no padded table, and is column-aware (no demangle unless `undecorated` is
selected). Select the columns you need — this is the fast path (`--format tsv|csv|jsonl`):
```bash
pdbsql app.pdb -q "SELECT name,rva,length FROM functions" --format jsonl -o funcs.jsonl --query-timeout 0 --quiet
pdbsql app.pdb -q "SELECT name,rva,length FROM functions" --format tsv   -o funcs.tsv   --query-timeout 0
```
`--dump <table>` is a `SELECT * FROM <table>` shortcut — handy, but for `functions`/`publics`
it pulls the expensive `undecorated` column, so prefer explicit columns for a fast bulk pull.

---

## Aggregates (built-in)

`blob_concat(value)` concatenates BLOB inputs and INTEGER 0-255 values
into one BLOB. NULL inputs are skipped; TEXT or out-of-range INTs error.
Use over an ordered row source, e.g.
`SELECT hex(blob_concat(x)) FROM (SELECT ... ORDER BY ...)`.

---

## Hex Address Formatting

RVAs are integers in SQL. Format as hex for readability:

```sql
-- 32-bit format
SELECT printf('0x%08X', rva) as addr FROM functions;

-- Variable width
SELECT printf('0x%X', rva) as addr FROM functions;

-- With size
SELECT name, printf('0x%X - 0x%X', rva, rva + length) as range FROM functions;
```

---

## Language Codes

The `language` column in `compilands` uses CV_CFL_* constants:

| Code | Language |
|------|----------|
| 0 | C |
| 1 | C++ |
| 2 | Fortran |
| 3 | MASM |
| 4 | Pascal |
| 5 | Basic |
| 6 | COBOL |
| 7 | LINK |
| 8 | CVTRES |
| 9 | CVTPGD |
| 10 | C# |
| 11 | Visual Basic |
| 12 | ILASM |
| 13 | Java |
| 14 | JScript |
| 15 | MSIL |
| 16 | HLSL |

`language` is **NULL** when the compiland reports none — roughly 10% of compilands
on a real shipping PDB carry no language record at all. It cannot be 0-for-unknown,
because 0 is a real value meaning C.

```sql
-- Count by language (NULL = the compiland records no language)
SELECT
  CASE
    WHEN language IS NULL THEN 'unknown'   -- must be the searched form, see below
    WHEN language = 0 THEN 'C'
    WHEN language = 1 THEN 'C++'
    WHEN language = 2 THEN 'Fortran'
    WHEN language = 3 THEN 'MASM'
    WHEN language = 7 THEN 'LINK'
    WHEN language = 8 THEN 'CVTRES'
    ELSE 'Other'
  END as lang,
  COUNT(*) as count
FROM compilands
GROUP BY lang
ORDER BY count DESC;
```

> ⚠️ Use the **searched** `CASE WHEN language IS NULL`, never the simple form
> `CASE language WHEN NULL THEN ...`. The simple form compares with `=`, and
> `NULL = NULL` is never true in SQL, so that branch silently never fires and the
> unknown rows fall through to `ELSE`. The same trap applies to every nullable
> column here: `udts.name`, `parameters.frame_offset`, `parameters.register`.

---

## Quick Start Examples

### "What's in this PDB?"

```sql
-- Function count
SELECT COUNT(*) FROM functions;

-- Type count
SELECT COUNT(*) FROM udts;

-- Source files
SELECT COUNT(*) FROM source_files;

-- Compilands
SELECT COUNT(*) FROM compilands;
```

### "Find the entry point"

```sql
-- Look for main/WinMain
SELECT * FROM functions WHERE undecorated LIKE '%main%';

-- Public symbols (exports)
SELECT * FROM publics ORDER BY name;
```

### "What types are defined?"

```sql
-- All UDTs
SELECT name, length FROM udts ORDER BY name;

-- All enums
SELECT name FROM enums ORDER BY name;

-- Largest types
SELECT name, length FROM udts ORDER BY length DESC LIMIT 20;
```

### "Source file information"

```sql
-- All source files
SELECT filename FROM source_files ORDER BY filename;

-- Header vs source files
SELECT
  CASE
    WHEN filename LIKE '%.h' OR filename LIKE '%.hpp' THEN 'header'
    WHEN filename LIKE '%.c' OR filename LIKE '%.cpp' THEN 'source'
    ELSE 'other'
  END as type,
  COUNT(*) as count
FROM source_files
GROUP BY type;
```

---

## Summary: When to Use What

| Goal | Table/Join |
|------|------------|
| List all functions | `functions` |
| Find types | `udts`, `enums`, `typedefs` |
| Top-N / distinct types | `udts`, `enums` (already deduplicated) |
| Per-compiland type records | `udt_records`, `enum_records` |
| Struct layout / data members | `udt_fields` |
| Methods / virtuals | `udt_methods` |
| Enum values | `enum_values` |
| Inheritance (upward) | `base_classes WHERE derived_name = X` |
| Source files | `source_files` |
| Line mapping | `line_numbers` |
| Compilands | `compilands` |
| PE sections | `sections` |
| Local variables | `locals WHERE func_id = X` |
| Parameters | `parameters WHERE func_id = X` |

**Remember:** Always filter function-scoped tables (`locals`, `parameters`) by `func_id` for performance.

---

## Troubleshooting startup failures

| Message | Cause | Fix |
|---|---|---|
| `Failed to create DiaSource: the DIA COM class is not registered ... and no usable msdia140.dll was found` | Neither COM registration nor a loadable `msdia140.dll` on disk | Install the Visual Studio C++ tools, drop `msdia140.dll` next to `pdbsql.exe`, or `regsvr32 "<VS>\DIA SDK\bin\amd64\msdia140.dll"` |
| `Failed to load PDB: ... not a DIA-readable PDB` | The file isn't an MSVC-emitted PDB | DIA cannot read LLVM/clang-emitted PDBs. Rebuild with MSVC, or use a different tool for that PDB |
| `Failed to load PDB: ... file not found or inaccessible` | Bad path or permissions | Check the path |
| `Failed to load PDB: ... signature/age mismatch` | PDB doesn't match its binary | Get the matching PDB |

pdbsql tries normal COM activation first, then falls back to loading
`msdia140.dll` directly (no registry write, no admin), so a machine with the SDK
present but unregistered works out of the box. Every failure carries its raw
`HRESULT` for reporting.

---

## Example Workflows

### Reverse Engineer a Type

```sql
-- 1. Find the type (deduplicated -- `udts` repeats a name per defining compiland)
SELECT name, length FROM udts WHERE name LIKE '%MyClass%';

-- 2. Its memory layout -- data members only, so `offset` is meaningful
SELECT name, offset, length, type
FROM udt_fields
WHERE udt_name = 'MyClass'
ORDER BY offset;

-- 3. Its interface -- member functions, with the virtual/pure flags
SELECT name, type, is_virtual, is_pure, is_static
FROM udt_methods
WHERE udt_name = 'MyClass'
ORDER BY is_virtual DESC, name;

-- 4. Its ancestors (walk upward -- the indexed direction)
WITH RECURSIVE anc(derived, base, depth) AS (
  SELECT derived_name, base_name, 1 FROM base_classes WHERE derived_name = 'MyClass'
  UNION ALL
  SELECT bc.derived_name, bc.base_name, a.depth + 1
  FROM base_classes bc JOIN anc a ON bc.derived_name = a.base WHERE a.depth < 8
)
SELECT DISTINCT base, depth FROM anc ORDER BY depth;

-- 5. Functions that touch it (type strings resolve, including pointers/refs)
SELECT DISTINCT f.name
FROM functions f
JOIN locals l ON f.id = l.func_id
WHERE l.type LIKE '%MyClass%';
```

### Map the polymorphic surface

`is_virtual` / `is_pure` live on `udt_methods`.

```sql
-- Classes ranked by how much virtual surface they expose
SELECT udt_name, COUNT(*) AS virtuals, SUM(is_pure) AS pure
FROM udt_methods
WHERE is_virtual = 1
GROUP BY udt_name
ORDER BY virtuals DESC
LIMIT 20;

-- Abstract classes / interfaces: anything with a pure virtual
SELECT DISTINCT udt_name FROM udt_methods WHERE is_pure = 1 ORDER BY udt_name;

-- One class's vtable-facing API
SELECT name, type, is_pure
FROM udt_methods
WHERE udt_name = 'MyClass' AND is_virtual = 1;
```

### Find every user of a type (type-string search)

Parameter, local and member type strings are built structurally, so pointers,
references, arrays and basic types all render (`const char*`, `MyClass&`,
`int[16]`, `double (void)`) and are searchable with `LIKE`.

```sql
-- Every function taking a pointer to this type
SELECT DISTINCT f.name, p.name AS param, p.type
FROM parameters p JOIN functions f ON f.id = p.func_id
WHERE p.type LIKE '%MyClass%*';

-- Structs embedding it by value
SELECT udt_name, name FROM udt_fields WHERE type = 'MyClass';

-- Raw-buffer smells: char/byte arrays inside structs
SELECT udt_name, name, type, length FROM udt_fields
WHERE type LIKE 'char[%' OR type LIKE 'unsigned char[%'
ORDER BY length DESC LIMIT 20;
```

### Toolchain forensics (per translation unit)

`compilands.language` reports the real per-TU source language (NULL when the
compiland records none).

```sql
-- What was this binary actually built from? (searched CASE -- see Language Codes)
SELECT CASE WHEN language IS NULL THEN 'unknown'
            WHEN language = 0 THEN 'C'    WHEN language = 1 THEN 'C++'
            WHEN language = 3 THEN 'MASM' WHEN language = 7 THEN 'LINK'
            WHEN language = 8 THEN 'CVTRES'
            ELSE 'other(' || language || ')' END AS lang,
       COUNT(*) AS tus
FROM compilands GROUP BY lang ORDER BY tus DESC;

-- Hand-written assembly TUs (often crypto / intrinsics / hot loops)
SELECT name FROM compilands WHERE language = 3;

-- Third-party static libs linked in
SELECT library, COUNT(*) AS tus FROM compilands
WHERE library <> '' GROUP BY library ORDER BY tus DESC LIMIT 20;
```

### Data and header budget

`data.length` resolves through the symbol's type, so global sizes are real.

```sql
-- Largest global/static data
SELECT name, length FROM data ORDER BY length DESC LIMIT 20;

-- Header bloat: which types are compiled into the most translation units?
SELECT name, COUNT(*) AS tus FROM udt_records
WHERE name IS NOT NULL GROUP BY name ORDER BY tus DESC LIMIT 20;
```

### Import stubs and jump thunks

`thunks` enumerates per compiland (tens of thousands on a large binary).

```sql
SELECT name, printf('0x%X', rva) AS addr, length FROM thunks
ORDER BY length DESC LIMIT 20;

-- Thunks clustered by section (import tables vs inline jump stubs)
SELECT section, COUNT(*) AS n, SUM(length) AS bytes
FROM thunks GROUP BY section ORDER BY n DESC;
```

> `symbol_at()` takes a **literal** address, not a column: it cannot be joined as
> `JOIN symbol_at(t.rva)`. To resolve a thunk's neighbourhood, read the rva first
> and issue `SELECT * FROM symbol_at(<that value>)` as a second query.

### Analyze Code Coverage

```sql
-- Functions with source line info
SELECT
  f.name,
  COUNT(DISTINCT ln.line) as line_count,
  f.length as code_bytes
FROM functions f
JOIN line_numbers ln ON ln.rva >= f.rva AND ln.rva < f.rva + f.length
GROUP BY f.id
ORDER BY line_count DESC
LIMIT 20;
```

### Find Unused Types

```sql
-- Types not referenced in locals or parameters. `udts` is already deduplicated,
-- so each unused type is reported once.
SELECT u.name
FROM udts u
WHERE NOT EXISTS (
  SELECT 1 FROM locals WHERE type LIKE '%' || u.name || '%'
)
AND NOT EXISTS (
  SELECT 1 FROM parameters WHERE type LIKE '%' || u.name || '%'
)
ORDER BY u.name;
```

> This is a whole-table scan of `locals` and `parameters` per candidate type — fine
> on a small PDB, very slow on a multi-GB one. Bound it with a `LIMIT` on the
> candidate set first.

---

## Server Modes

PDBSQL runs two server modes: **HTTP REST** (`--http`, recommended for scripts/agents) and **MCP** (`--mcp`, for MCP clients).

---

### HTTP REST Server (Recommended)

Standard REST API that works with curl, any HTTP client, or LLM tools.

**Starting the server:**
```bash
# HTTP REST, default port 8080
pdbsql database.pdb --http

# Custom port and bind address
pdbsql database.pdb --http 9000 --bind 0.0.0.0

# With authentication (HTTP only; the MCP endpoint is unauthenticated)
pdbsql database.pdb --http 8080 --token mysecret

# Bound query timeout (seconds; 0 = no limit; default 60) — seeds runtime_settings
pdbsql database.pdb --http 8080 --query-timeout 120

# MCP server (default: random port 9000-9999)
pdbsql database.pdb --mcp
```

**HTTP Endpoints:**

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Welcome message |
| `/help` | GET | No | API documentation (for LLM discovery) |
| `/query` | POST | Yes* | Execute SQL (body = raw SQL) |
| `/status` | GET | No | Health check — O(1) liveness (no symbol scan; can't hang), always unauthenticated so uptime/LB probes work even with `--token` set |
| `/shutdown` | POST | Yes* | Stop server |

*Auth required only if `--token` was specified (`/help` and `/status` are always exempt).

**Example with curl:**
```bash
# Get API documentation
curl http://localhost:8080/help

# Execute SQL query
curl -X POST http://localhost:8080/query -d "SELECT name, rva FROM functions LIMIT 5"

# With authentication
curl -X POST http://localhost:8080/query \
     -H "Authorization: Bearer mysecret" \
     -d "SELECT * FROM udts"

# Check status
curl http://localhost:8080/status
```

**Response Format (JSON).** Each response is a multi-statement envelope; results are
under `results[]`, one entry per statement:
```json
{"success": true, "statement_count": 1,
 "results": [{"statement_index": 0, "success": true,
              "columns": ["name", "rva"], "rows": [["main", "4096"]],
              "row_count": 1, "elapsed_ms": 0.1, "error": null}],
 "row_count_total": 1, "elapsed_ms_total": 0.1, "first_error_index": null}
```
On error, the failing statement carries `"success": false` and an `"error"` string.
A query that hits the timeout returns `"success": true` with the **partial** rows.

**Low-memory streaming:** add the header `X-XSQL-Stream: 1` to the `POST /query` and
the same envelope is streamed row-by-row (chunked), keeping peak memory at ~one row.

