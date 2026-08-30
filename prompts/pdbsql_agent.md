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
row.

> **The first lookup in a session takes a few seconds; every one after is
> instant.** The "O(1)" above is the steady state — DIA builds its address
> index lazily on first use. Do **not** conclude from one slow lookup that
> `symbol_at` is unsuitable for bulk symbolization: it is the right primitive,
> and the cost is paid once per session, not per address. `--warm-tables
> functions` reduces the first call but does not remove it. If you are
> symbolizing a batch, issue the first lookup and continue.

> **Symbolizing MANY addresses? Batch them — one query per address is 17x
> slower.** `symbol_at` takes a **correlated** argument, so a whole address
> list resolves in a single query. warm:
>
> | approach | rate | 1M addresses |
> |---|---|---|
> | one query per address | 937/sec | **~18 min** |
> | `json_each` batch (2,000 addrs) | **16,260/sec** | **~62 s** |
>
>
> Nearly all of the single-lookup cost is per-request overhead (`symbol_at`
> itself is ~0 ms warm), which is why amortizing the request is the whole win.
>
> **Two traps make batching look impossible when it is not:**
> - **Send `Content-Type: text/plain`.** The common form-urlencoded default is
>   parsed into params under a small cap, so a batch over ~8 KB comes back
>   **HTTP 413 "payload too large"** even though the server's real limit is
>   **64 MiB**. The 413 reads as "batches this big are refused" — it is not.
> - **Use `json_each`, not `UNION ALL`.** A compound `SELECT … UNION ALL …`
>   caps at **500 terms**, and exceeding it returns **HTTP 200** carrying
>   `"too many terms in compound SELECT"` with zero rows — so a caller
>   checking only the status code sees a successful empty result.
>   `json_each` has no such limit and is faster per address anyway.

**This is a general rule, not a `symbol_at` quirk.** Any workload shaped
"for each of N things, ask pdbsql about it" should be ONE query, never N.
On two unrelated shapes:

| workload | one query per item | batched | ratio |
|---|---|---|---|
| `symbol_at(addr)` | 937/sec | 16,260/sec | **17x** |
| `udts WHERE name = ?` | 598/sec | 10,000/sec | **16x** |

The lookups themselves are ~0 ms warm, so a loop is paying HTTP round-trip and
planning cost per item — and because the server runs queries one at a time,
those costs cannot overlap. The loop form's ceiling is the per-request rate
(~600-940/sec *however cheap* the query is); the batched form is bounded by
real work. Resolving 100 type names: **167 ms** looped vs **10 ms** batched.

> **Sizing a NAME batch: cost depends on WHICH names, not how many.** Exact
> name lookup spans **~0.19 ms to ~20 ms per name — a ~100x spread** — and
> heavily-templated C++ names sit at the expensive end. Two *equal* 500-name
> batches from the same PDB, both resolving 500/500:
>
> | batch | time | per name |
> |---|---|---|
> | mostly plain names (28% templated) | **93 ms** | 0.19 ms |
> | mostly templated (69% templated) | **11,343 ms** | 22.7 ms |
>
> So do **not** extrapolate a batch's cost from a sample of simple names: the
> 500-name figure above predicts ~0.4 s for 2,000 names, and the observed
> answer is **23 s**. If a name batch is unexpectedly slow, it is the *names*
> — not the batch size, and not unresolved entries (verified: those batches
> resolved completely).
>
> **Two factors, and they interact.** 100 names per cell:
>
> | | plain | templated |
> |---|---|---|
> | **early** in the type enumeration | **0.09 ms** | **0.11 ms** |
> | **late** in the type enumeration | **2.81 ms** | **29.83 ms** |
>
> - **Where the type sits dominates** — 31x for plain names alone, shape held
>   constant.
> - **Template shape only matters for late names** (a further ~10x). Among
>   early names it costs nothing.
>
> The practical read: **names you have just scanned are effectively free to
> resolve; arbitrary names from deep in the type space are not.** A workload
> that scans and then resolves what it saw stays fast. One that resolves a
> list of names from elsewhere can hit ~30 ms each.
>
> Do **not** bucket by name shape alone — `oo2::vector<oo2::LRM *>` (early,
> templated) is 0 ms while `hkArrayView<wchar_t>` (late, templated) is ~25 ms,
> same nesting and similar length. Two other rules also fail: long names are
> **not** slower (a 65-char plain name beats a 33-char templated one), and the
> slow names are **not** unresolved ones falling to the glob path (those
> batches resolved 100%).
>
> **Size name batches empirically**: start around 500, measure, grow while the
> time holds. Re-running does not help — expensive names stay expensive across
> warm repeats.
>
> Batching itself is *not* the overhead: the same 20 expensive names cost
> **517 ms** issued one-by-one and **481 ms** batched. `json_each` is still
> the right construct — it just cannot make an intrinsically expensive name
> cheap.
>
> **Addresses have no such effect** — 2,000 `symbol_at` addresses cost 123 ms,
> because an address is an address. Batch those freely.

Batch form (one query, any number of addresses):

```sql
WITH addrs(a) AS (SELECT value FROM json_each('[74008528, 74008536]'))
SELECT a, (SELECT name FROM symbol_at(a)) AS sym FROM addrs;
```

> **`addr` is the INPUT, `rva` is the OUTPUT.** `WHERE rva = <x>` does *not*
> bind the query address — it filters the matched symbol's start, leaving the
> hidden input unbound, so the call returns **zero rows** rather than an error.
> Use `symbol_at(<addr>)` or `WHERE addr = <addr>`. (A returned `rva` may be
> lower than the `addr` you asked about; that is the point — it resolves
> mid-symbol addresses.) This is the fast addr→symbol primitive for symbolization — unlike `functions WHERE
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

-- Resolve a known address to a data symbol -- pushed down (see Performance & Fast Paths)
SELECT name FROM data WHERE rva = 74008528;
```

#### udts
User-defined types (structs, classes, unions).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INT | Type ID |
| `name` | TEXT | Type name |
| `length` | INT | Size in bytes |

> **Finding candidate types by prefix is the expensive step — budget for it,
> or avoid it.** In a 3-step subsystem profile, the `udts` prefix
> search was **95% of the total** (18.4 s of 19.5 s); the batched field counts
> and scoped child lookups together took ~1 s.
>
> | entry strategy | cost |
> |---|---|
> | `udts WHERE name LIKE 'Prefix%'` | **18.4 s** |
> | `udt_records WHERE name LIKE 'Prefix%'` | 18.5 s (dedup is not the cost) |
> | **`functions WHERE name LIKE 'Prefix%::%'`** | **0.4-0.8 s** |
> | `udts WHERE name = '<exact>'` | **0 ms** |
>
> Since C++ methods are named `Type::method`, deriving class names from
> `functions` and then resolving each exactly is **16.5x faster end to end**
> (1,176 ms vs 19,460 ms on the same task, returning the same ranking):
>
> **It only finds types that HAVE METHODS.** A POD struct with no member
> functions never appears in `functions`, so this silently misses it — it
> surfaced 16 candidates where the `udts` prefix found 40. Use it to explore a
> class-heavy subsystem cheaply; use the `udts` prefix when completeness over
> plain-data structs matters, and budget the ~18 s.

Deriving candidate class names from method names (the cheap entry above):

```sql
SELECT DISTINCT substr(name, 1, instr(name, ':') - 1) AS cls
FROM functions WHERE name LIKE 'FPostProcess%::%' LIMIT 40;
```

> **`udts` gives you one row per distinct type.** DIA emits a type record per
> *compiland that defines the type*, so the underlying debug info repeats names
> heavily (raw records collapse to substantially fewer distinct names).
> `udts` deduplicates; **`udt_records`** exposes the raw per-compiland rows for
> the rare questions that need them.
>
> **`name` is NULL for anonymous types.** DIA labels them `<unnamed-tag>` /
> `<anonymous-tag>`, but those are display placeholders, not names: many unrelated
> types share one and they cannot be looked up by name. They are reported as NULL
> and are never merged with each other. Match them with `IS NULL`, never `= '...'`.

> **"Largest structure" is two different questions — pick deliberately.**
> By BYTE SIZE (`udts.length`, no join, slow but doable) and by MEMBER
> COUNT (`JOIN udt_fields`, see the cost warning on that table) return
> completely different answers on the same PDB: the largest by size is
> typically a big state struct, while the largest by field count is often a
> compiler-generated closure.
>
> **For the member-count reading, filter compiler-generated types or the
> answer is useless.** 15% of struct names are `<lambda…>` closures or
> `::__l…` function-local types, and they occupy the entire top of a
> field-count ranking — 7 rows of compiler artefacts before the first
> hand-written type (`FPostProcessSettings`, 1,278 fields) appears. Add
> `AND udt_name NOT LIKE '%<lambda%' AND udt_name NOT LIKE '%::__l%'`.
>
> **`GROUP BY udt_name` over `udt_fields` DOUBLE-COUNTS.** `udt_fields`
> rows are keyed to the RAW per-compiland records, so grouping by NAME sums
> a type's fields once per duplicate record. A type with two records of 639
> fields each is reported as **1,278** fields when it actually has **639**.
> Aggregate per `udt_id` first, then reduce by name — this is exactly the
> distinction `udts` (deduplicated) vs `udt_records` (raw) exists to express.
>
> **A name filter on `udt_fields` does NOT make it cheaper.** `udt_name`
> has no pushdown (`EXPLAIN` → `VIRTUAL TABLE INDEX 0`), so
> `WHERE udt_name LIKE 'Prefix%'` still walks the full table and takes
> ~170 s — essentially the same as no filter. Only `udt_id` pushes down
> (`INDEX 1`, ~0 ms). So: for ONE known type, resolve its `id` from `udts`
> and scope by `udt_id`. For a whole-table ranking there is no cheap live
> path at all — export once and query the export (see the bulk-export
> section).
>
> **The byte-size ranking needs no such filter** — its top-5 is
> byte-for-byte identical with and without it. Compiler-generated types do
> get large (biggest ≈1 MB) but stay below the real top-5, so filtering
> there only risks hiding a legitimately huge allocator block. Filter for
> "most members", not for "biggest".

```sql
-- Largest structures BY SIZE -- no duplicates, no filter needed
SELECT name, length FROM udts WHERE name IS NOT NULL ORDER BY length DESC LIMIT 10;

-- PER-PARENT AGGREGATES: key on the child's id column, driven by a BOUNDED
-- parent set -- never a GROUP BY over the child table. A correlated subquery
-- (below) and an explicit JOIN are EQUIVALENT; use whichever reads better.
-- Warm, same answer (n=639): JOIN 1 ms, correlated subquery 1 ms.
-- Both plan optimally -- `udts u JOIN udt_fields f ON f.udt_id = u.id WHERE
-- u.name = '...'` gives `SCAN u ... INDEX 2` (name) + `SCAN f ... INDEX 1`
-- (udt_id), i.e. parent by name then child by id, which is exactly right.
-- The join SHAPE is not a performance lever: when such a query is slow it is
-- the PARENT-side predicate, not the join. A prefix on udts costs 41,459 ms
-- with the join and 41,455 ms without it -- the join adds 4 ms; the glob is
-- the whole cost (the same prefix on `functions` takes 659 ms). If a joined
-- query is slow, look at how you reach the parent, not at the join.
-- Every parent->child pair here has a pushed-down id on the
-- child (udts->udt_fields/udt_methods via udt_id, udts->base_classes via
-- derived_id, enums->enum_values via enum_id), so the child table is never
-- walked. All collapse to the driving udts
-- scan (~48s) regardless of how expensive the child table is:
--     udt_fields   155s full walk  -> 46s
--     base_classes 129s full walk  -> 48s
--     udt_methods  >280s (would not complete) -> 49s
-- That last one is the point: it is otherwise unanswerable live.
SELECT u.name,
       (SELECT COUNT(*) FROM udt_fields f WHERE f.udt_id = u.id) AS fields
FROM udts u
WHERE u.name LIKE 'FPostProcess%'
ORDER BY fields DESC LIMIT 10;

-- Member count for a KNOWN type: scope by udt_id, which pushes down.
-- THE OPERATOR MATTERS MORE THAN THE COLUMN:
--     WHERE udt_id  = <id>      INDEX 1   ~0-500 ms   <- best
--     WHERE udt_name = 'Exact'  INDEX 2     ~946 ms   <- also pushed, fine
--     WHERE udt_name LIKE 'P%'  INDEX 0     ~170 s    <- NOT pushed
-- An exact `udt_name =` IS pushed down and is a reasonable way to scope one
-- type; it is the LIKE form that walks the full table and applies the filter
-- afterwards. Prefer udt_id when you already hold an id (about 2x cheaper
-- still), but do not rewrite a working `udt_name = 'Exact'` into a subquery
-- expecting a large win -- there is not one.
SELECT COUNT(*) AS fields FROM udt_fields
WHERE udt_id = (SELECT id FROM udts WHERE name = 'FPostProcessSettings');

-- NOTE the id comes from a NAME lookup, not typed in as a literal. That is
-- load-bearing, not stylistic. DIA builds its id index by WALKING, so a cold
-- `WHERE udt_id = <literal N>` realizes every symbol up to N first.
-- Same type, same answer:
--     WHERE udt_id = 400000            (raw literal id)    21,868 ms
--     WHERE udt_id = (SELECT id ... name = '...')             989 ms   <- 22x
-- First-touch cost by id: id 500 -> 0 ms, 5,000 -> 1.5 s, 100,000 -> 2.3 s,
-- 400,000 -> 17 s. Resolving by NAME uses DIA's name index and hands the
-- subquery an already-realized symbol, so the id index is never walked.
-- An id you already saw earlier in THIS session is realized and free; an id
-- you have not touched is not. Always reach the parent by name.
--
-- THIS IS NOT A udt_id QUIRK -- it applies to EVERY parent-id column, and
-- each symbol kind has its OWN index, so paying one does not help another:
--     parameters  WHERE func_id = 400000  (cold)          8,817 ms
--     enum_values WHERE enum_id = 900000  (after that)   41,565 ms
--     enums by name + correlated subquery (id ~700,000)      928 ms
-- WORST CASE IS AN ID THAT DOES NOT EXIST: it cannot short-circuit, so it
-- walks the ENTIRE id space and returns nothing. A wrong id is not
-- cheap-and-empty; it is the most expensive query you can issue. Never
-- guess an id -- resolve it by name.

-- Which types are compiled into the most translation units? (header bloat)
-- ~61 s on a large PDB -- it GROUP BYs every udt_records row and
-- therefore EXCEEDS THE 60 s DEFAULT TIMEOUT. Send an explicit larger bound
-- (X-XSQL-Timeout, in ms) or start the server with --query-timeout, or it
-- returns partial results. Also filter compiler-generated types or the answer
-- is useless: unfiltered, the top rows are `::__l<N>::` function-local types
-- and `<lambda_N>` closures, not the headers you are hunting.
SELECT name, COUNT(*) AS tus FROM udt_records
WHERE name IS NOT NULL
  AND name NOT LIKE '%<lambda%' AND name NOT LIKE '%::__l%'
GROUP BY name ORDER BY tus DESC LIMIT 10;

-- Find types by name pattern
SELECT * FROM udts WHERE name LIKE '%Config%';
```

> ⚠️ `SELECT COUNT(*) FROM udts` walks every type record and can exceed the default
> 60 s timeout on a multi-GB PDB. A `LIMIT` stays cheap (deduplication streams), so
> prefer bounded queries; raise `query_timeout_ms` deliberately if you truly need a
> whole-table count.
>
> **— and the cost is NOT about row count.** A full
> `COUNT(*)` per table:
>
> | fast (live is fine) | | slow (see cause below) | |
> |---|---|---|---|
> | `sections` | 0 ms | `labels` | 12.5 s |
> | `compilands` | 3 ms | `enums` | 45.5 s |
> | `source_files` | 174 ms | `enum_records` | 46.3 s |
> | `typedefs` | 354 ms | `udt_records` | 50.8 s |
> | `data` | 363 ms | `udts` | 58.0 s |
> | `publics` | 1.0 s | `line_numbers` | **> 2 min** |
> | `thunks` | 1.1 s | `udt_fields` | ~155 s |
> | `functions` | 2.2 s | `base_classes` | **168.6 s** |
> | | | `udt_methods` | **> 14 min** |
>
> The slow column has **three distinct causes**, not one: the UDT/Enum
> realization cost (`udts`, `enums`, `*_records`); a *parent walk* in the
> child tables (`udt_fields`, `udt_methods`, `base_classes` walk every
> UDT; `labels` walks every function); and per-compiland line
> enumeration (`line_numbers`).
>
> **Read that table as `COUNT(*)` cost, not scan cost — they are not the same
> thing.** `COUNT(*)` on `functions`/`publics`/`data` takes a count shortcut
> that never enumerates; on `udts`/`enums` there is no shortcut and the count
> *is* a full walk. So the table above compares a shortcut against a real scan
> for those rows. Both ways:
>
> | table | `COUNT(*)` | actual scan (`SELECT id …`) |
> |---|---|---|
> | `functions` | 0.40 s | **14.4 s** |
> | `publics` | 0.29 s | **18.6 s** |
> | `udts` | 56.8 s | 54.5 s |
> | `enums` | 44.6 s | 44.7 s |
>
> The UDT/Enum realization penalty is **real but ~4x per row, not 26x**:
> `functions` scans fully in ~14.4 s against `udts` in
> 54.5 s (~44 µs/row). Prefer `functions`/`publics` where the question allows
> — but budget for the difference being single-digit, not two orders of
> magnitude, once you are actually reading rows rather than counting them.
>
> **The worst cases are far past the default timeout, and row count does not
> predict them.** `base_classes` costs **2.8 minutes** — 3x
> the bare `udts` count — and `udt_methods` did **not finish a plain
> `COUNT(*)` in 850 seconds** (14.2 min, i.e. 14x the default timeout). Its
> true cost is *unknown*: no measurement has yet run it to completion. Both
> are *child* tables of the UDT family, so they pay
> the full UDT walk **plus** per-child work; `base_classes` has 4x
> *fewer* rows than `udt_records` yet costs 3x more. Do not size these from
> `SELECT COUNT(*)`-style intuition.
>
> Three consequences worth acting on: **(1)** if a question can be phrased
> against `functions`/`publics` instead of `udts`/`enums`, do that — the gap
> is 20-160x, not marginal; **(2)** an unscoped whole-table query over
> `udt_fields`/`udt_methods`/`base_classes` **will** blow the 60 s default —
> pass an explicit larger bound (`X-XSQL-Timeout: <ms>`, note **milliseconds**)
> or scope it, rather than discovering the timeout; **(3)** for these tables
> prefer a *scoped* question (`WHERE udt_id = …`, which pushes down and
> answers in milliseconds **provided the id came from a name lookup** — a
> cold literal id costs a walk proportional to its value, up to ~22 s; see
> the note under the example above) over an aggregate — see the correlated-subquery
> pattern above. A whole-table aggregate here is an export-and-cache job, not
> a live query.

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
> list. `WHERE id = <id>` and `WHERE rva = <addr>` are both indexed (a direct
> DIA lookup, same as `functions`/`publics`); `WHERE name = '<name>'` is **not**
> — it scans, and can't be pushed down the way `id`/`rva` can, since DIA's
> name-index lookup only searches the global symbol scope, which holds neither
> kind. These tables are NOT small on a large PDB — 
> tens of thousands of labels on a large PDB — so an unscoped scan costs real time, and
> `rva=`/`id=` are a win over it.
>
> **`labels` is far more expensive than `thunks`, and the row counts do not
> tell you that.** Because a nested scan walks *parents*, the cost tracks the
> **parent** population, not the number of rows returned. On the same
> large PDB:
>
> | table | parents walked | full scan |
> |---|---|---|
> | `thunks` | compilands | **1.1 s** |
> | `labels` | every function | **12.5 s** |
>
> `labels` returns only 1.9x more rows than `thunks` but costs **12x** more,
> because it asks every function for its labels to find a fraction of them —
> 46 parents per label returned. For scale, `typedefs` (a flat global table)
> scans fully in a fraction of a second, or ~19 µs/row. So **treat an unscoped
> `SELECT … FROM labels` on a large PDB as a ~12 s query, not a small-table
> query**, and scope it with `rva=`/`id=` (or a `LIMIT`, which streams
> normally at ~430 µs/row) whenever you can.

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

```sql
SELECT name, type, 'field'  AS kind FROM udt_fields  WHERE udt_name = 'MyClass'
UNION ALL
SELECT name, type, 'method' AS kind FROM udt_methods WHERE udt_name = 'MyClass';
```

> Methods typically outnumber fields ~7:1 on a large C++ PDB, so don't reach for
> the union unless you actually want both.
>
> For virtual **inheritance** (not virtual methods), use `base_classes.is_virtual`.

> **⚠ `udt_fields`/`udt_methods` WITHOUT `WHERE udt_name = '<name>'` walk every
> member of every UDT in the PDB — minutes for a bare
> `COUNT(*) FROM udt_fields` on a large PDB. This is the same inherent DIA
> UDT-realization cost that makes `COUNT(*) FROM udts` slow, now paid per
> member instead of per type —
> `LIMIT` does NOT save you if the query also has `GROUP BY`/`ORDER BY`/
> `DISTINCT` (those force materializing everything before the limit/sort can
> apply — the exact `GROUP BY func_id` trap documented in Performance & Fast
> Paths, same shape, different table). Always add `WHERE udt_name = X` when
> you have a specific type in mind; an unscoped cross-type query (e.g. "every
> struct with a `char[]` member") has no fast path on a large PDB and should
> be expected to take minutes, not treated as a query that merely needs a
> `LIMIT`.**

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

-- Abstract classes (have at least one pure virtual) -- SLOW on a large PDB: unscoped
-- DOES NOT COMPLETE on a large PDB, and its partial result looks like an
-- answer: `is_pure` has NO pushdown (INDEX 0), so this walks all of
-- udt_methods -- a table that does not finish a plain COUNT(*) in 850 s.
-- timed out at both 60 s and 150 s, returning only partial counts
-- neither of which is the full set. ALWAYS check `timed_out` on this
-- shape, or scope it to one class with `WHERE udt_name = '<Exact>'` (INDEX 2).
SELECT DISTINCT udt_name FROM udt_methods WHERE is_pure = 1;

-- Public API surface of a class
SELECT name, type FROM udt_methods
WHERE udt_name = 'MyClass' AND access = 'public';

-- Find all pointer fields -- SLOW on a large PDB: unscoped (no udt_name filter)
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

**Performance:** `WHERE filename LIKE 'prefix%'` pushes down to DIA's own
glob search (same mechanism as the functions/publics/data name LIKE
pushdown) — but only a *prefix* pattern qualifies; a leading-wildcard
pattern (like the header-file example below) has no usable prefix and
falls back to a full scan. Source files are cheap to enumerate either way
(no expensive per-symbol realization the way UDT/Enum types have), so this
is a modest speedup, not a dramatic one — the full unscoped scan itself is
already fast.

```sql
-- List all source files
SELECT filename FROM source_files ORDER BY filename;

-- Find header files -- leading wildcard, NOT pushed down (still correct, just a full scan)
SELECT filename FROM source_files WHERE filename LIKE '%.h' OR filename LIKE '%.hpp';

-- Filter by directory -- pushed down (real prefix)
SELECT filename FROM source_files WHERE filename LIKE 'C:\Engine\Source\%';
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

**Address -> source line: `WHERE rva` is ALSO pushed down** (`VIRTUAL TABLE
INDEX 2000`), and it is the filter you actually have when starting from an
address. ~0 ms at several addresses on a large PDB. Without it the
only documented filters are `file_id`/`compiland_id` — neither of which you
know yet — and the fallback is an unscoped scan that does **not** complete.
Use a bounded window ending at the target and take the last line at or before
it:

```sql
SELECT file_id, line FROM line_numbers
WHERE rva <= 50020200 AND rva > 50020100 ORDER BY rva DESC LIMIT 1;
```

Full `addr -> symbol -> source line` costs ~175 ms warm (the `symbol_at` half
pays its one-time ~2.7 s on the session's first call — see `symbol_at`).
Give the range a tight lower bound like any other rva range.

**Performance:** `WHERE compiland_id = <id>` and `WHERE file_id = <id>` both push
down to a scoped DIA lookup (fast — a single compiland's or a single file's line
records) instead of walking every compiland in the PDB. An unscoped scan, or a
scan filtered only through a JOIN predicate without a resolved literal (like the
`sf.filename LIKE` example below — the file_id isn't known until the join runs),
falls back to the full walk and can take minutes on a large PDB. When you already
know the `file_id` (e.g. from a prior `source_files` lookup), filter on it
directly for the fast path: `SELECT ... FROM line_numbers WHERE file_id = 42`.

```sql
-- Lines in a specific file (file_id unknown up front — falls back to a full
-- walk; resolve file_id first if you need this fast on a large PDB)
SELECT line, printf('0x%X', rva) as addr
FROM line_numbers ln
JOIN source_files sf ON ln.file_id = sf.id
WHERE sf.filename LIKE '%main.cpp'
ORDER BY line;

-- Fast path: file_id already known
SELECT line, printf('0x%X', rva) as addr FROM line_numbers WHERE file_id = 42 ORDER BY line;

-- Find code density (lines per RVA) -- SLOW on a large PDB: unscoped full walk
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
-- Prefix search: pushed down to DIA's glob search, fast even on huge PDBs
SELECT name, rva, length FROM functions WHERE name LIKE 'Init%';

-- Substring/suffix search: no pushdown, a full table walk (see Performance & Fast Paths)
SELECT name, rva, length FROM functions WHERE name LIKE '%Init%';

-- Undecorated search (C++ name mangling removed) — no pushdown, plus pays the demangle
SELECT undecorated, rva FROM functions WHERE undecorated LIKE '%vector%';
```

### Type Information Analysis

> Both queries below are unscoped full scans over the whole type graph (no
> `WHERE udt_name =`, and the second needs every `udts` row before `GROUP BY`
> can emit anything) — expect minutes on a large PDB, same cost class as the
> `udt_fields`/`udts` warnings above.

```sql
-- Find all structs with a specific member.  165 s (2.75 min) for 25
-- rows on a large PDB -- the field `name` has NO pushdown (INDEX 0), so this
-- walks every udt_fields row. It DOES complete, unlike the is_pure shape
-- above, but it EXCEEDS THE 60 s DEFAULT: pass a larger X-XSQL-Timeout or you
-- get a partial list that looks complete. There is no scoped alternative --
-- searching by field name is inherently a full walk (udt_name/udt_id push
-- down, `name` does not).
SELECT DISTINCT udt_name
FROM udt_fields
WHERE name = 'dwSize';

-- Struct size distribution -- SLOW on a large PDB: unscoped udts + GROUP BY
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
-- Functions by source file. DOES NOT COMPLETE on a large PDB: it has been
-- left running for minutes and returns ZERO rows. The GROUP BY
-- must finish before any row is emitted, so unlike a streaming query there is
-- no partial output to salvage: you wait, then get nothing. It joins across
-- all of line_numbers, a table that cannot even be COUNTed unscoped.
-- Do NOT run this shape against a multi-GB PDB.
-- Scope to ONE file instead -- file_id pushes down and answers in ~200 ms:
--   SELECT COUNT(*) FROM line_numbers WHERE file_id = <id>;
-- (resolve <id> first via source_files WHERE filename LIKE '%name%', ~134 ms)
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
-- Object file statistics. DOES NOT COMPLETE on a large PDB -- timed
-- out at 123 s returning ZERO rows. Same shape as "Functions by source file"
-- above: a GROUP BY across all of line_numbers, which emits nothing until the
-- aggregate finishes, so a timeout yields no partial result to salvage.
-- For one object file, scope by compiland_id (pushes down) instead.
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

- **`SELECT COUNT(*) FROM <table>` is fast for MOST tables** — `functions`,
  `publics`, `data`, `typedefs`, `compilands` ask DIA for the count directly and
  never materialize rows.
  ```sql
  SELECT COUNT(*) FROM functions;   -- returns in ~a second, even on a huge PDB
  ```
  **Exception: `udts`/`udt_records`/`enums`/`enum_records`/`udt_fields`/
  `udt_methods` have NO fast count** — DIA has to realize every UDT/Enum
  symbol to count it (same cost `WHERE name LIKE` pays on these tables, see
  below), and `udt_fields`/`udt_methods` pay it per MEMBER on top. On
  a large PDB: `COUNT(*) FROM udts` ~61s; `COUNT(*) FROM udt_fields`
   **185.7s**. A bare `COUNT(*)` on these six tables is not a
  cheap sanity check — treat it like any other unscoped full scan.
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

- **`WHERE compiland_id = <id>` and `WHERE file_id = <id>` on `line_numbers` push
  down to a scoped DIA lookup** instead of walking every compiland in the PDB.
  Unscoped access (no filter, or a filter only reachable through a JOIN
  predicate DIA can't see as a literal) falls back to the full walk, which
  can run for minutes on a large PDB.
  ```sql
  SELECT line, rva FROM line_numbers WHERE file_id = 42;         -- pushed down, fast
  SELECT line, rva FROM line_numbers WHERE compiland_id = 7;     -- pushed down, fast
  SELECT COUNT(*) FROM line_numbers;                              -- full walk, can take minutes
  ```
  The **first** `file_id`-scoped query in a session pays a one-time warm-up
  (DIA lazily builds its file-id index; 10-18s on a large PDB) — every subsequent `file_id`-scoped query in that same session is then
  tens of milliseconds. `compiland_id` has no such warm-up. **`X-XSQL-Timeout`
  cannot cut the warm-up short**: the warm-up produces no rows until it
  finishes, so nothing polls the deadline while it runs — a short timeout
  still reports `timed_out` correctly and the query does terminate, but only
  after paying the full warm-up cost, not the requested budget. On a
  large PDB: a **2 s** budget on the first `file_id` query of a fresh
  session returned at **8.9 s**. (This is *not* the same as the rva-range
  window described below — that one **is** interruptible now. The difference
  is where the time goes: a bad rva landing spends it in a walk loop that
  polls for cancellation, whereas this warm-up is a single DIA index build
  with no loop to poll.) The warm-up itself is never
  wasted, though: even a timed-out first query leaves the session's index
  built, so a retry (or any other `file_id`-scoped query) right after is
  fast — raise the timeout for the first query, don't repeat it hoping for
  a cheaper outcome. If you control server startup, **`--warm-file-index`**
  pays this cost once at launch instead, so no client ever sees it.
- **The FIRST query touching `functions`, `publics`, `data`, `udts`,
  `typedefs`, `enums`, or `compilands` on a fresh session pays its own,
  separate one-time DIA warm-up per table** — unrelated to the file_id
  warm-up above. A bounded query like `SELECT name FROM functions LIMIT
  1000` ~2.8s cold vs ~0.03-0.04s once warm (~70-90x) on a
  large PDB (`publics`/`data`/`udts`/`typedefs`/`enums` show the
  same shape at comparable or larger magnitude; `compilands` is
  negligible); the cost is a large fixed hit on the first row plus a
  decaying per-row ramp that only converges to the warm rate around row
  ~500,000, so a *bounded* query pays disproportionately more per row than
  a full-table dump would. If you control server startup,
  **`--warm-tables <comma-list>`** pays this cost once at launch instead
  for whichever tables you list (composable with `--warm-file-index` —
  they warm unrelated DIA state). Be deliberate about including `udts`/
  `enums` in the list: those symbol kinds are ~19x more expensive to
  realize per-symbol than `functions`, so fully warming either on a huge
  PDB can itself take tens of seconds — worth it if you'll query them, not
  if you won't. **This is not just a time cost — it is also a large,
  PERMANENT memory commitment.** (Bypassing pdbsql
  entirely, timing DIA itself): walking all
  every function on a large PDB grew the process by **gigabytes**,
  and that memory is never released for the life of the session — DIA
  caches what it has realized permanently, the same mechanism behind the
  warm-up speed benefit, just visible on the memory axis instead of the
  time axis. Warming several large tables at once
  (`--warm-tables functions,udts,enums,typedefs`) can commit several GB of
  RAM to the process for its entire lifetime, not just delay startup by a
  few tens of seconds — budget server memory accordingly, and warm only
  the tables you actually expect to query heavily.
- **The slowest tables are deliberately NOT warmable, and no flag will make
  them fast.** `--warm-tables` omits `base_classes`, `udt_fields`,
  `udt_methods` and `labels` — the most expensive tables in the schema — on
  purpose, because warming cannot help them. Their cost is
  **re-enumeration on every query** (walk every UDT or every function,
  `findChildren` on each), not a one-time index build, so nothing is cached
  between queries and there is nothing to pre-pay. `base_classes`
  on a fully `udts`-warm server ran 127.5 s, then **134.4 s on an immediate
  repeat** — no improvement at all from having just done it. Warming it at
  startup would cost ~2 minutes of boot and save nothing. So do not treat a
  slow `base_classes`/`udt_methods` query as a warm-up problem: the answer
  is to **scope** it (`WHERE udt_id = …`, milliseconds) or export once and
  query the cache.
- **`WHERE rva = <addr>` on `functions`/`publics`/`data`/`thunks`/`labels` is a direct DIA address lookup**
  (findSymbolByRVA), NOT a walk — it is the fast addr→name primitive, and a
  *repeated* lookup of the same address is genuinely free (sub-millisecond).
  It is not, however, true O(1): each *new* address pays a real, variable
  DIA-side seek cost (typically low-single-digit ms, occasionally tens of
  ms, depending on where that address lands — the same seek characteristic
  that makes bounded-range queries erratic, see below). For a handful of
  addresses this is invisible; for a bulk-symbolization batch of hundreds to
  thousands of *distinct* addresses, budget roughly a few ms per new address
  rather than assuming instant (800 distinct addresses on a
  large PDB, 1.79s total, ~2.2ms/address average). `WHERE name = '<exact>'` and
  `WHERE id = <n>` push down too. **`data`/`thunks`/`labels` do NOT get the
  bounded-range form** (`rva > / >= / < / <=`) that `functions`/`publics`
  have — all three are a small minority of DIA's address-ordered symbol
  stream, so an open-ended range there has to walk past every other-kind
  symbol in between; does not finish in 30s for a 15-row sample on a
  large PDB (confirmed for `data`; declined for `thunks`/`labels` by the
  same reasoning rather than re-measuring an already-established trap).
  `thunks`/`labels` also have no `name=` pushdown at all — see their table
  sections above.
  **Known limitation on `rva=`**: if more than one symbol genuinely shares
  the exact same start address (real on `data` — e.g. duplicate CFG
  guard-check entries), the pushdown returns exactly one of them, not every
  tied row; a manual scan filtered to that rva can return more.
  ```sql
  SELECT name FROM functions WHERE rva = 73623824;  -- pushed down, not a full-table walk
  SELECT rva  FROM functions WHERE name = 'CalcHash';
  ```
- **`WHERE name LIKE 'prefix%'` on `functions`/`publics`/`data` also pushes down** —
  DIA's own glob search, not a client-side walk. 3-9x faster than a full
  scan on a large PDB. Only a *leading-wildcard* pattern (`'%suffix'`,
  `'%substring%'`) falls back to a full walk — DIA has no way to seek into that.
  ```sql
  SELECT name, rva FROM functions WHERE name LIKE 'Curl_%';   -- pushed down, fast
  SELECT name, rva FROM functions WHERE name LIKE '%Init%';   -- full walk, no pushdown
  ```
  The pushdown is a correctness superset (SQLite always re-applies the exact
  pattern), so results are identical either way — this is purely a speed
  distinction. **`typedefs` gets the same real speedup. `udts`/`enums` also
  push down `name LIKE 'prefix%'` (and correctly preserve their
  one-row-per-distinct-type dedup), but it is NOT a meaningful speedup** —
  DIA realizes every UDT/Enum symbol to determine anything about it
  (including a name match), the same reason `COUNT(*) FROM udts` has no fast
  path either. Use it for a scoped/deduplicated answer, not for speed.
  `undecorated LIKE ...` has no pushdown at all (no DIA name index
  over demangled names) and also pays the demangle per candidate row.

  **How large that gap is:** same SQL shape, same query plan, ~45x apart on
  comparable table sizes — and the cost is DIA's, confirmed by timing DIA
  directly with no pdbsql in the path:
  ```
  functions WHERE name LIKE 'Prefix%'   ->  1.3 s   (DIA glob index works)
  udts      WHERE name LIKE 'Prefix%'   -> 53.9 s   (= the UNFILTERED scan;
                                                     the filter buys nothing)
  ```
  **On `udts`/`enums`, prefer `WHERE name = 'Exact'` — it is essentially
  instant** (DIA's exact-name index works for every tag, ~0 ms even on
  those two). This is the one case where the usual "a prefix is nearly as
  good as an exact match" intuition is badly wrong: on those tables the
  prefix costs a full ~50 s table walk while the exact match is free.

  ⚠️ **But only when the name EXISTS.** A `name =` lookup that matches
  nothing falls back to the expensive wildcard search (needed because DIA's
  exact index cannot see certain compiler-generated closure names), so a
  MISS costs ~54 s while a hit costs ~0 ms. Probing speculative names one
  at a time on these two tables is therefore very slow; if you are checking
  whether a type exists at all and might be wrong, prefer a bounded
  `LIKE 'Prefix%'` (one ~50 s scan that answers for every candidate at
  once) over repeated `name =` misses. Note
  they answer *different questions* — an exact lookup finds only
  `Prefix`, not `PrefixAllocator` or `Prefix::Nested::<lambda_1>` — so use
  it when you genuinely know the type name, and accept the walk (or the
  bulk-export/cache route below) when you truly need the prefix set.
- **`WHERE rva > / >= / < / <= <addr>` on `functions`/`publics` is a BOUNDED range**
  lookup (one address-index seek + a forward walk that stops at the upper bound) — use
  it for "what's in this address window", not as a substitute for `LIMIT`/`OFFSET`
  paging of the whole table. For a full-table pull, use a plain unbounded `SELECT`
  with `X-XSQL-Stream` (HTTP) or `--dump`/`--format jsonl` (CLI) instead.
  ```sql
  SELECT name, rva FROM functions WHERE rva > 0x140010000 AND rva < 0x140020000;
  ```
  **ALWAYS give the range a tight UPPER bound — omitting it costs ~5,500x for
  the identical rows.** "Stops at the upper bound" is the whole mechanism: with
  no upper bound the walk drains the entire address space, and the address
  enumerator yields **every symbol kind** (not just the one you asked for),
  each discarded one at a time. all three returning
  the **same 925 rows**:

  | query | cost |
  |---|---|
  | `WHERE rva > 186241964` | **121,128 ms** |
  | `WHERE rva > 186241964 AND rva < 4294967295` | **> 60 s (timeout)** |
  | `WHERE rva > 186241964 AND rva < 186441965` | **22 ms** |

  Note the middle row: an upper bound placed *past the last symbol* is no
  better than none, because the walk still runs to the end. Padding to
  `0xFFFFFFFF` does not help — the bound must actually cut the walk short. If
  the question really is "everything after X", take the ceiling from
  `SELECT MAX(rva) FROM functions` (~16 s once on a large PDB) and use
  `max + 1`, rather than leaving the range open.

  This is also why **`ORDER BY rva DESC` does not complete** on a large PDB
  while ascending `ORDER BY rva` costs 21 ms: only the ascending direction is
  claimed by the index, so `DESC` forces a full materialize. For "the N
  highest addresses", select a tail window with a tight two-sided range and
  reverse the rows client-side.
  **Cost is driven by WHERE the window lands, not how wide it is or how many rows
  it returns.** The seek is not O(1): most windows resolve in single-digit
  milliseconds regardless of size, but a window landing in an unlucky address
  region can take 10+ seconds even for a modest window with a normal row count
  (a 0x10000-byte window with an ordinary row count took ~14s in one region,
  vs ~8ms for a similar-sized/row-count window elsewhere) — and it does NOT warm
  up on repeat, unlike a flat `rva=` lookup. A sweep of eleven 200 KB windows
  across a large PDB found ten at 0-43 ms and one at **7.6 s**; zooming in
  located a ~2 MB band where it peaks at **28.3 s**. Note what the worst window
  returned: **zero rows**. Cost here is *anti*-correlated with result size —
  the 28.3 s window found nothing, while a neighbouring window returned 1,295
  rows in 43 ms. Do not infer that a slow range query is "returning a lot". **The effect is size-dependent**: that
  ~14s worst case was on a large PDB, while the same sweep across a much
  smaller one found *no* cliff at all. Expect it on multi-GB PDBs; don't design
  around it on small ones. **`X-XSQL-Timeout` DOES bound this** (it did not used to): the cost turns out
  to be in the walk, not in the seek, and that loop now polls for cancellation,
  so a bad landing is interruptible at a bounded overshoot. Against the
  28.3 s window above: a 1 s budget returned at 1.43 s, 5 s at 5.23 s, 10 s at
  10.01 s, each reporting `timed_out`. `POST /cancel` is accepted too. **A
  stalled range query no longer requires restarting the server** — bound it and
  retry elsewhere.
- **`symbol_at(<addr>)` resolves an address INSIDE a symbol → the containing symbol**
  (of any kind), also via findSymbolByRVA — the true symbolization primitive,
  with the same per-new-address seek cost as flat `rva=` above (not literal
  O(1), see there for the numbers).
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
- **`ORDER BY` silently defeats `LIMIT`'s early-exit — a general SQL trap, not a
  DIA one.** `LIMIT N` with no `ORDER BY` lets the engine stop as soon as it has N
  matching rows, however expensive each row is to test (a slow correlated
  `NOT EXISTS`/`LIKE '%…%'` filter included). Adding `ORDER BY` needs every
  candidate proved before the first N can be known, so it silently reverts to
  evaluating the WHOLE unfiltered set no matter how small the `LIMIT` is — the
  query looks nearly identical but the cost is not. On the
  "unused types" query below (610 UDTs, a `NOT EXISTS (… LIKE '%'||u.name||'%')`
  filter against each): `LIMIT 10` alone returns in ~0.6s; the identical query
  with `ORDER BY u.name` added (`... LIMIT 10 ORDER BY u.name`) does not finish
  in 20s. This applies to any expensive filter on any table, not just this
  example — if a `LIMIT`ed query is slower than expected, check for an
  `ORDER BY` first. If you need the results sorted, sort them client-side
  after fetching a bounded, unsorted batch rather than asking the server to
  sort before limiting.
  ```sql
  SELECT u.name FROM udts u
  WHERE NOT EXISTS (SELECT 1 FROM locals WHERE type LIKE '%' || u.name || '%')
  LIMIT 10;
  ```
- **…but do NOT "fix" that by swapping `ORDER BY` for a threshold — it is
  position luck, not a speedup.** The natural reaction to the trap above is to
  rewrite a top-N as a threshold filter, e.g. `WHERE length > 1000000 LIMIT 5`
  instead of `ORDER BY length DESC LIMIT 5`. on a large PDB that *looks* like a
  16x win (3.1 s vs 49.0 s) **and returns the correct top-5** — but it is not a
  win, and the next threshold you pick may cost the full scan and return
  nothing:

  | query | result | cost |
  |---|---|---|
  | `… WHERE length > 1000000 LIMIT 5` | 5 rows (correct) | **3.1 s** |
  | `… WHERE length > 99000000 LIMIT 5` | **0 rows** | **48.3 s** |

  `length` has **no pushdown** (`EXPLAIN QUERY PLAN` shows
  `VIRTUAL TABLE INDEX 0:…` — index 0 means no constraint was pushed) and DIA
  indexes nothing by size, so the engine is plainly scanning until `LIMIT` is
  satisfied. The first query was fast only because the few multi-megabyte
  structs happen to enumerate early. **You cannot pick a correct threshold
  without already knowing the answer**, and a wrong one costs the full scan *and*
  gives you nothing. If a `LIMIT`ed query on a non-pushed-down column looks
  surprisingly fast, re-run it with a threshold that matches nothing: if that
  costs the full scan, the speedup was luck. For a genuine whole-table top-N or
  median, use the export-and-cache route (dump once, query the cache) rather
  than hunting for a threshold.

### Your slow query blocks everyone else on the server

The DIA session is not thread-safe, so the server executes queries **one at
a time**. A long query does not just cost *you* time — every other client
waits for it. `SELECT COUNT(*) FROM sections` costs 1.5 ms on its
own, but **11.2 s** when issued 2 s into a 12.5 s scan.

This changes what an unscoped query means on a shared server. The costs
listed elsewhere in this document — `base_classes` 168 s, `udt_methods`
> 850 s, `line_numbers`/`udt_fields` unable to finish a plain `COUNT(*)` —
are each, on a shared server, a multi-minute stall **for everyone**. So:

- **Bound every exploratory query.** Send `X-XSQL-Timeout` rather than
  relying on the default; the cap is what limits the blast radius, and it is
  **verified to work even on the worst tables** — bounded at 3 s, a
  `udt_methods` scan (> 850 s unbounded) stops at 3.018 s and a trivial query
  issued 1 s later returns in 1.972 s, versus 11,210 ms behind an *unbounded*
  12.5 s scan. A blocked client waits only the slow query's **remaining
  budget**, so the bound you choose is very close to the worst stall you
  impose on everyone else.
- **Prefer the scoped forms** described above — they finish in milliseconds
  and never become the blocker.
- **Do not "just try" a whole-table aggregate** on a server other people are
  using. Export once and query the cache instead.

`/status` and `/help` bypass the executor and stay responsive during a stall
, so a healthy `/status` is **not** evidence that
the server can currently answer a query.

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
**Picking explicit columns fixes the TIME cost, not the memory cost.** A full-table bulk
walk of a large symbol table — column-limited or not, `--dump` or explicit columns, streamed
or buffered — permanently commits several GB of RAM to the process for the rest of its
lifetime; that memory comes from the underlying engine realizing each symbol as it's walked,
not from the response you asked for, and it is never released once paid. A 147 MB bulk
a full-table export a ~3.9 GB process footprint even with the demangle-free fast
path selected. If you'll run further large queries afterward, budget for that memory staying
resident; if the process is short-lived (export, exit), it doesn't matter.

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

> The first two queries below are unscoped cross-type scans (`GROUP BY`/
> `DISTINCT` over the whole table) — on a large PDB, expect **minutes**, the
> same UDT-realization cost as `udt_fields`/`udt_methods` without
> `WHERE udt_name =` (see the warning above). Only the third, scoped to one
> class, is fast. Reach for the first two only when you actually need a
> cross-type ranking, not as a routine way to explore one class.

```sql
-- Classes ranked by how much virtual surface they expose (SLOW on a large PDB)
SELECT udt_name, COUNT(*) AS virtuals, SUM(is_pure) AS pure
FROM udt_methods
WHERE is_virtual = 1
GROUP BY udt_name
ORDER BY virtuals DESC
LIMIT 20;

-- Abstract classes / interfaces: anything with a pure virtual (SLOW on a large PDB)
-- DOES NOT COMPLETE on a large PDB, and its partial result looks like an
-- answer: `is_pure` has NO pushdown (INDEX 0), so this walks all of
-- udt_methods -- a table that does not finish a plain COUNT(*) in 850 s.
-- timed out at both 60 s and 150 s, returning only partial counts
-- neither of which is the full set. ALWAYS check `timed_out` on this
-- shape, or scope it to one class with `WHERE udt_name = '<Exact>'` (INDEX 2).
SELECT DISTINCT udt_name FROM udt_methods WHERE is_pure = 1 ORDER BY udt_name;

-- One class's vtable-facing API (fast: scoped to one udt_name)
SELECT name, type, is_pure
FROM udt_methods
WHERE udt_name = 'MyClass' AND is_virtual = 1;
```

### Find every user of a type (type-string search)

Parameter, local and member type strings are built structurally, so pointers,
references, arrays and basic types all render (`const char*`, `MyClass&`,
`int[16]`, `double (void)`) and are searchable with `LIKE`.

> The `parameters`/`locals` queries here are fine (`functions`/`parameters`
> are cheap to realize, per Performance & Fast Paths). The `udt_fields`
> queries are the SAME unscoped cross-type scan warned about above —
> `type = 'MyClass'` gets no DIA pushdown either (`type` is a rendered
> string, not a name DIA indexes) and the `ORDER BY ... LIMIT 20` on the
> third query still has to touch every field first. Expect minutes on a
> large PDB for either.

```sql
-- Every function taking a pointer to this type
SELECT DISTINCT f.name, p.name AS param, p.type
FROM parameters p JOIN functions f ON f.id = p.func_id
WHERE p.type LIKE '%MyClass%*';

-- Structs embedding it by value (SLOW on a large PDB: unscoped udt_fields scan)
SELECT udt_name, name FROM udt_fields WHERE type = 'MyClass';

-- Raw-buffer smells: char/byte arrays inside structs (SLOW on a large PDB: same reason)
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
-- ~61 s on a large PDB -- GROUP BY over every udt_records row,
-- so it EXCEEDS THE 60 s DEFAULT TIMEOUT: pass a larger X-XSQL-Timeout (ms) or
-- --query-timeout, or you get partial results. The compiler-artefact filter is
-- required too, or the top rows are `::__l<N>::` locals and `<lambda_N>`
-- closures rather than headers.
SELECT name, COUNT(*) AS tus FROM udt_records
WHERE name IS NOT NULL
  AND name NOT LIKE '%<lambda%' AND name NOT LIKE '%::__l%'
GROUP BY name ORDER BY tus DESC LIMIT 20;
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

> `symbol_at` takes a **literal** address, not a column: it cannot be joined as
> `JOIN symbol_at(t.rva)`. To resolve a thunk's neighbourhood, read the rva first
> and issue `SELECT * FROM symbol_at(<that value>)` as a second query.

### Analyze Code Coverage

```sql
-- Functions with the most source-line coverage. DOES NOT COMPLETE on a large
-- PDB -- timed out at 90 s returning ZERO rows. It joins every
-- function against all of line_numbers and then aggregates; nothing is emitted
-- until the GROUP BY completes. Scope to one function's rva range instead
-- (ln.rva >= f.rva AND ln.rva < f.rva + f.length for a SINGLE known f).
SELECT
  f.name,
  COUNT(DISTINCT ln.line) as line_count,
  f.length as code_bytes
FROM functions f
CROSS JOIN line_numbers ln ON ln.rva >= f.rva AND ln.rva < f.rva + f.length
GROUP BY f.id
ORDER BY line_count DESC
LIMIT 20;
```

> **Use `CROSS JOIN`, not plain `JOIN`, for this query shape.** `line_numbers`
> has a pushdown for exactly this correlation (`WHERE rva >= X AND rva < Y`,
> backed by DIA's `findLinesByRVA` — essentially free per function), but
> SQLite's query planner
> picks `line_numbers` as the driving/outer table for a plain `JOIN` here
> (its own cost heuristic, not something the pushdown's existence changes),
> and the correlation can only be pushed down when `functions` drives the
> join. `CROSS JOIN` is standard SQL for exactly this: it keeps the written
> table order instead of letting the optimizer reorder it. 
> the plain-`JOIN` form of this exact query took 60+ seconds on a SMALL PDB
> (full re-scan of `line_numbers` per function) and did not finish at all on
> a large one; the `CROSS JOIN` form above takes ~0.2s on that same small
> PDB and ~35s on another large PDB (the full pushdown-driven
> per-function walk, correctness-verified against a direct query).

### Find Unused Types

```sql
-- Types not referenced in locals or parameters. `udts` is already deduplicated,
-- so each unused type is reported once. LIMIT with no ORDER BY lets the engine
-- stop as soon as it has enough matches, instead of proving every candidate.
SELECT u.name
FROM udts u
WHERE NOT EXISTS (
  SELECT 1 FROM locals WHERE type LIKE '%' || u.name || '%'
)
AND NOT EXISTS (
  SELECT 1 FROM parameters WHERE type LIKE '%' || u.name || '%'
)
LIMIT 20;
```

> This is a whole-table scan of `locals` and `parameters` per candidate type --
> fine on a small PDB, slow on a large one. `LIMIT` alone bounds it because the
> engine can stop once it has enough rows; adding `ORDER BY u.name` defeats
> that -- sorting needs every candidate proved first, so it silently reverts to
> scanning the whole `udts` table (all its LIKE scans included) before
> returning a single row. If you need the results sorted, sort them client-side
> after fetching a bounded, unsorted batch.

---

## Server Modes

PDBSQL runs two server modes: **HTTP REST** (`--http`, recommended for scripts/agents) and **MCP** (`--mcp`, for MCP clients).

### This document is served by the tool itself

You are reading pdbsql's complete reference. It is compiled into the binary and
available at runtime from **both** server modes, so an agent never has to be given
it out of band:

| mode | how to fetch this document |
|---|---|
| HTTP | `GET /help` — REST mechanics, then this document |
| MCP | the **`pdbsql_help`** tool — takes no arguments, returns this document verbatim |

The MCP server exposes exactly two tools: **`pdbsql_query`** (execute SQL) and
**`pdbsql_help`** (this reference). pdbsql ships no skills package, so this file is
the only guidance that exists — if you are an agent that has not read it, fetch it
before writing queries against a large PDB.

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

# Pay the line_numbers file_id warm-up at startup, not on the first query
# (see "Indexed lookups" above — this only matters if you plan to run
# WHERE file_id = X queries; skip it otherwise, it just delays startup)
# Works the same way with --mcp.
pdbsql database.pdb --http 8080 --warm-file-index

# Pay one or more tables' own one-time DIA warm-up at startup instead of on
# their first real query (see the performance notes above -- unrelated to
# --warm-file-index, composable with it). Valid names: functions, publics,
# data, udts, typedefs, enums, compilands. Works the same way with --mcp.
pdbsql database.pdb --http 8080 --warm-tables functions,publics,data

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

