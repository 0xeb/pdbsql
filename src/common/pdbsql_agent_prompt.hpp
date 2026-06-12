// Auto-generated from pdbsql_agent.md
// Generated: 2026-05-31T20:38:47.744305
// DO NOT EDIT - regenerate with: python scripts/embed_prompt.py

#pragma once

namespace pdbsql {

inline constexpr const char* SYSTEM_PROMPT =
    R"PROMPT(# PDBSQL Agent Guide

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
- Members accessible via `udt_members` table
- Base classes via `base_classes` table

### Compilands
**Compilands** represent object files (`.obj`) that were linked:
- `name` - Object file name
- `library` - Static library if applicable
- `language` - Source language (C, C++, etc.)

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

```sql
-- Largest structures
SELECT name, length FROM udts ORDER BY length DESC LIMIT 10;

-- Find types by name pattern
SELECT * FROM udts WHERE name LIKE '%Config%';
```

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

### Type Detail Tables

#### udt_members
Members of structs/classes/unions.

| Column | Type | Description |
|--------|------|-------------|
| `udt_id` | INT | Parent UDT ID |
| `udt_name` | TEXT | Parent UDT name |
| `id` | INT | Member ID |
| `name` | TEXT | Member name |
| `type` | TEXT | Member type |
| `offset` | INT | Offset within parent |
| `length` | INT | Member size |
| `access` | INT | Access modifier (DIA enum: 1=private, 2=protected, 3=public) |
| `is_static` | INT | 1 if static member |
| `is_virtual` | INT | 1 if virtual member |

```sql
-- Members of a specific struct
SELECT name, offset, length, type
FROM udt_members
WHERE udt_name = 'MyStruct'
ORDER BY offset;

-- Find all pointer members
SELECT udt_name, name FROM udt_members WHERE type LIKE '%*%';
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

```sql
-- Find all derived classes of a base
SELECT derived_name FROM base_classes WHERE base_name = 'IUnknown';

-- Inheritance hierarchy
WITH RECURSIVE hierarchy AS (
  SELECT derived_name, base_name, 0 as depth FROM base_classes WHERE derived_name = 'MyClass'
  UNION ALL
  SELECT bc.derived_name, bc.base_name, h.depth + 1
  FROM base_classes bc
  JOIN hierarchy h ON bc.derived_name = h.base_name
  WHERE h.depth < 5
)
SELECT * FROM hierarchy;
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
PE sections from section contributions.

| Column | Type | Description |
|--------|------|-------------|
| `number` | INT | Section number |
| `rva` | INT | Section RVA |
| `length` | INT | Section size |
| `characteristics` | INT | Section flags |
| `readable` | INT | 1 if readable |
| `writable` | INT | 1 if writable |
| `executable` | INT | 1 if executable |
| `code` | INT | 1 if code section |

```sql
-- Code sections
SELECT number, printf('0x%X', rva) as addr, length
FROM sections WHERE executable = 1;

-- Data sections
SELECT number, printf('0x%X', rva) as addr, length
FROM sections WHERE writable = 1 AND executable = 0;
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
| `location_type` | INT | DIA location enum (0=null, 1=static, 2=regrel, 4=enregistered, etc.) |
| `offset_or_register` | INT | Stack offset (when location_type=regrel) or register number (when enregistered) |

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
| `location_type` | INT | DIA location enum |
| `offset_or_register` | INT | Stack offset or register number (per location_type) |

```sql
-- Parameters of a specific function
SELECT name, type
FROM parameters
WHERE func_name = 'MyFunction';
```

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
FROM udt_members
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
-- All classes implementing an interface
WITH RECURSIVE derived AS (
  SELECT derived_name, base_name, 1 as level
  FROM base_classes WHERE base_name = 'IUnknown'

  UNION ALL

  SELECT bc.derived_name, bc.base_name, d.level + 1
  FROM base_classes bc
  JOIN derived d ON bc.base_name = d.derived_name
  WHERE d.level < 10
)
SELECT DISTINCT derived_name, level FROM derived ORDER BY level, derived_name;
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

## Performance Guidelines

### Use Equality Filters

```sql
-- FAST: Uses constraint pushdown
SELECT * FROM locals WHERE func_id = 12345;

-- SLOW: Full scan
SELECT * FROM locals WHERE func_name LIKE '%main%';
```

### Limit Result Sets

```sql
-- Use LIMIT for exploration
SELECT * FROM functions LIMIT 100;

-- Combine with ORDER BY for top-N
SELECT name, length FROM functions ORDER BY length DESC LIMIT 10;
```

### Index-Friendly Queries

```sql
-- Exact matches are fastest
SELECT * FROM udts WHERE name = 'MyStruct';

-- LIKE with leading wildcard is slowest
SELECT * FROM udts WHERE name LIKE '%Struct%';

-- LIKE without leading wildcard is faster
SELECT * FROM udts WHERE name LIKE 'My%';
```

---

## Aggregates (libxsql built-in)

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
| 10 | C# |)PROMPT"
    R"PROMPT(| 11 | Visual Basic |
| 12 | ILASM |
| 13 | Java |
| 14 | JScript |
| 15 | MSIL |
| 16 | HLSL |

```sql
-- Count by language
SELECT
  CASE language
    WHEN 0 THEN 'C'
    WHEN 1 THEN 'C++'
    WHEN 2 THEN 'Fortran'
    ELSE 'Other'
  END as lang,
  COUNT(*) as count
FROM compilands
GROUP BY language;
```

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
| Type members | `udt_members` |
| Enum values | `enum_values` |
| Inheritance | `base_classes` |
| Source files | `source_files` |
| Line mapping | `line_numbers` |
| Compilands | `compilands` |
| PE sections | `sections` |
| Local variables | `locals WHERE func_id = X` |
| Parameters | `parameters WHERE func_id = X` |

**Remember:** Always filter function-scoped tables (`locals`, `parameters`) by `func_id` for performance.

---

## Example Workflows

### Reverse Engineer a Type

```sql
-- 1. Find the type
SELECT * FROM udts WHERE name LIKE '%MyClass%';

-- 2. Get its members
SELECT name, offset, length, type
FROM udt_members
WHERE udt_name = 'MyClass'
ORDER BY offset;

-- 3. Check base classes
SELECT base_name FROM base_classes WHERE derived_name = 'MyClass';

-- 4. Find functions using this type
SELECT f.name
FROM functions f
JOIN locals l ON f.id = l.func_id
WHERE l.type LIKE '%MyClass%';
```

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
-- Types not referenced in locals or parameters
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

---

## Server Modes

PDBSQL supports two server protocols for remote queries: **HTTP REST** (recommended) and raw TCP.

---

### HTTP REST Server (Recommended)

Standard REST API that works with curl, any HTTP client, or LLM tools.

**Starting the server:**
```bash
# Default port 8081
pdbsql database.pdb --http

# Custom port and bind address
pdbsql database.pdb --http 9000 --bind 0.0.0.0

# With authentication
pdbsql database.pdb --http 8081 --token mysecret
```

**HTTP Endpoints:**

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Welcome message |
| `/help` | GET | No | API documentation (for LLM discovery) |
| `/query` | POST | Yes* | Execute SQL (body = raw SQL) |
| `/status` | GET | Yes* | Health check |
| `/shutdown` | POST | Yes* | Stop server |

*Auth required only if `--token` was specified.

**Example with curl:**
```bash
# Get API documentation
curl http://localhost:8081/help

# Execute SQL query
curl -X POST http://localhost:8081/query -d "SELECT name, rva FROM functions LIMIT 5"

# With authentication
curl -X POST http://localhost:8081/query \
     -H "Authorization: Bearer mysecret" \
     -d "SELECT * FROM udts"

# Check status
curl http://localhost:8081/status
```

**Response Format (JSON):**
```json
{"success": true, "columns": ["name", "rva"], "rows": [["main", "4096"]], "row_count": 1}
```

```json
{"success": false, "error": "no such table: bad_table"}
```

)PROMPT";

} // namespace pdbsql
