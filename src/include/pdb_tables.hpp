// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
/**
 * pdb_tables.hpp - PDB entity virtual tables
 *
 * Defines virtual tables for PDB symbols using the xsql vtable framework.
 * Tables are streaming (generator_table) so full scans are lazy (LIMIT stops early),
 * and common equality predicates are pushed down (xBestIndex) for speed.
 *
 * Tables:
 *   functions     - Function symbols (name, rva, length, etc.)
 *   publics       - Public symbols (exports, etc.)
 *   data          - Global/static data symbols
 *   udts          - User-defined types (structs, classes, unions)
 *   enums         - Enumerations
 *   typedefs      - Type aliases
 *   compilands    - Object files / compilation units
 *   source_files  - Source file paths
 *   line_numbers  - Source line to RVA mapping
 *   sections      - PE sections from the SECTIONHEADERS debug stream (named)
 *   thunks        - Thunk symbols (import stubs, etc.)
 *   labels        - Code labels
 *   udt_members   - UDT member fields (struct/class members)
 *   enum_values   - Enum value constants
 *   base_classes  - Base class relationships
 *   locals        - Local variables (per function)
 *   parameters    - Function parameters (per function)
 */

#include <xsql/xsql.hpp>
#include <xsql/database.hpp>
#include <xsql/runtime_settings_table.hpp>
#include "pdb_session.hpp"
#include "pdb_runtime_settings.hpp"
#include <algorithm>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>

namespace pdbsql {

// Import xsql types into pdbsql namespace for convenience
using xsql::create_vtable;
using xsql::GeneratorTableDef;
using xsql::generator_table;
using xsql::register_generator_vtable;

// ============================================================================
// Symbol Cache Structures
// ============================================================================

struct CachedSymbol {
    DWORD id = 0;
    std::string name;
    std::string undecorated;
    DWORD rva = 0;
    ULONGLONG length = 0;
    DWORD symtag = 0;
    DWORD section = 0;
    DWORD offset = 0;
};

struct CachedCompiland {
    DWORD id = 0;
    std::string name;
    std::string library_name;
    std::string source_file;
    DWORD language = 0;          // CV_CFL_C, CV_CFL_CXX, etc. -- only meaningful when
    bool has_language = false;   // has_language; not every compiland reports one.
};

struct CachedSourceFile {
    DWORD id = 0;
    std::string filename;
    DWORD checksum_type = 0;
    std::string checksum;
};

struct CachedLineNumber {
    DWORD file_id = 0;
    DWORD line = 0;
    DWORD column = 0;
    DWORD rva = 0;
    DWORD length = 0;
    DWORD compiland_id = 0;
};

struct CachedSection {
    DWORD section_number = 0;
    std::string name;
    DWORD rva = 0;
    DWORD length = 0;
    DWORD characteristics = 0;
    bool read = false;
    bool write = false;
    bool execute = false;
    bool code = false;
};

struct CachedMember {
    DWORD parent_id = 0;
    std::string parent_name;
    DWORD id = 0;
    std::string name;
    std::string type_name;
    DWORD offset = 0;
    ULONGLONG length = 0;
    DWORD access = 0;  // 1=private, 2=protected, 3=public
    bool is_static = false;
    bool is_virtual = false;
    bool is_pure = false;
    // Data members and member functions are both UDT children, distinguished here
    // so `offset` (data-only) can report NULL on function rows and callers can
    // restrict to the historical data-only view with `WHERE kind = 'data'`.
    bool is_function = false;
};

struct CachedEnumValue {
    DWORD enum_id = 0;
    std::string enum_name;
    DWORD id = 0;
    std::string name;
    int64_t value = 0;
};

struct CachedBaseClass {
    DWORD derived_id = 0;
    std::string derived_name;
    DWORD base_id = 0;
    std::string base_name;
    DWORD offset = 0;
    bool is_virtual = false;
    DWORD access = 0;
};

struct CachedLocal {
    DWORD func_id = 0;
    std::string func_name;
    DWORD id = 0;
    std::string name;
    std::string type_name;
    DWORD location_type = 0;
    // A single offset_or_register column meant different things depending on
    // location_type, so a reader had to consult a sibling column to know what the
    // number was. Split: each is set only when it applies, NULL otherwise.
    bool has_frame_offset = false;
    int64_t frame_offset = 0;
    bool has_register = false;
    int64_t register_id = 0;
    // Source order of a parameter. DIA emits children in order, but SQL promises
    // no row order without ORDER BY, so a signature could not be reconstructed
    // reliably without this.
    int64_t ordinal = 0;
};

// ============================================================================
// Streaming Generators (lazy full scans; LIMIT-friendly)
// ============================================================================

inline size_t to_size_t_clamped(LONG v) {
    if (v <= 0) return 0;
    return static_cast<size_t>(v);
}

// Cheap planner row-count hint for the symbol tables. estimate_rows() is called
// by the vtable's xBestIndex during planning of EVERY query on the table (not
// just COUNT), so it must be cheap: it must NOT call DIA's get_Count, whose cost
// scales with the number of symbols realized and can be seconds on a large PDB.
// estimate_rows is only an optimizer hint (estimatedRows/estimatedCost) and never
// affects results; the exact count still comes from row_count() on the
// COUNT_ONLY_SCAN path. A deliberately large value keeps the planner treating
// these as big tables (vs libxsql's 1000 GeneratorTableDef default, which would
// under-estimate ~1000x and invite bad nested-loop join plans).
constexpr size_t kSymbolRowEstimate = 1000000;

inline std::string safe_symbol_name(IDiaSymbol* symbol) {
    if (!symbol) return "";
    SafeBSTR name;
    if (SUCCEEDED(symbol->get_name(name.ptr()))) {
        return name.str();
    }
    return "";
}

// CV basic-type code -> C++ spelling. The width matters: DIA reports `int`,
// `short` and `__int64` all as bt=6 (btInt), distinguished only by length.
inline std::string base_type_spelling(DWORD base_type, ULONGLONG length) {
    switch (base_type) {
        case btVoid:    return "void";
        case btChar:    return "char";
        case btWChar:   return "wchar_t";
        case btInt:
            switch (length) {
                case 1:  return "signed char";
                case 2:  return "short";
                case 8:  return "__int64";
                default: return "int";
            }
        case btUInt:
            switch (length) {
                case 1:  return "unsigned char";
                case 2:  return "unsigned short";
                case 8:  return "unsigned __int64";
                default: return "unsigned int";
            }
        case btFloat:   return length == 4 ? "float" : "double";
        case btBool:    return "bool";
        case btLong:    return "long";
        case btULong:   return "unsigned long";
        case btBSTR:    return "BSTR";
        case btHresult: return "HRESULT";
        case btCurrency:return "CURRENCY";
        case btDate:    return "DATE";
        case btVariant: return "VARIANT";
        case btComplex: return "complex";
        case btBit:     return "bit";
        case btChar16:  return "char16_t";
        case btChar32:  return "char32_t";
        case btNoType:  return "";
        default:        return "";
    }
}

// Render a readable type name for ANY type symbol.
//
// A bare get_name() only works for named types (UDT/enum/typedef). Basic types,
// pointers, arrays and function types have NO name in DIA, so get_name() returns
// an empty string for them -- which is why most `parameters.type` values used to
// come back blank. Building the name structurally fixes all of them.
inline std::string type_name_of(IDiaSymbol* type, int depth = 0) {
    if (!type || depth > 8) return "";

    DWORD tag = 0;
    if (FAILED(type->get_symTag(&tag))) return "";

    auto cv_prefix = [&](IDiaSymbol* s) {
        std::string p;
        BOOL f = FALSE;
        if (SUCCEEDED(s->get_constType(&f)) && f) p += "const ";
        if (SUCCEEDED(s->get_volatileType(&f)) && f) p += "volatile ";
        return p;
    };

    switch (tag) {
        case SymTagBaseType: {
            DWORD bt = 0;
            ULONGLONG len = 0;
            type->get_baseType(&bt);
            type->get_length(&len);
            return cv_prefix(type) + base_type_spelling(bt, len);
        }
        case SymTagPointerType: {
            CComPtr<IDiaSymbol> inner;
            type->get_type(&inner);
            BOOL is_ref = FALSE;
            type->get_reference(&is_ref);
            // A pointer's own const/volatile is TOP-LEVEL cv ("char * const") and
            // belongs after the star; the pointee's cv already comes back inside
            // the recursive call. Prefixing here yields "const const char*".
            std::string suffix;
            BOOL f = FALSE;
            if (SUCCEEDED(type->get_constType(&f)) && f) suffix += " const";
            if (SUCCEEDED(type->get_volatileType(&f)) && f) suffix += " volatile";
            return type_name_of(inner, depth + 1) + (is_ref ? "&" : "*") + suffix;
        }
        case SymTagArrayType: {
            CComPtr<IDiaSymbol> inner;
            type->get_type(&inner);
            DWORD count = 0;
            type->get_count(&count);
            return cv_prefix(type) + type_name_of(inner, depth + 1) + "[" + std::to_string(count) + "]";
        }
        case SymTagFunctionType: {
            CComPtr<IDiaSymbol> ret;
            type->get_type(&ret);
            std::string out = type_name_of(ret, depth + 1) + " (";
            CComPtr<IDiaEnumSymbols> args;
            bool first = true;
            if (SUCCEEDED(type->findChildren(SymTagFunctionArgType, nullptr, nsNone, &args)) && args) {
                for (;;) {
                    CComPtr<IDiaSymbol> arg;
                    ULONG fetched = 0;
                    if (FAILED(args->Next(1, &arg, &fetched)) || fetched != 1) break;
                    CComPtr<IDiaSymbol> arg_type;
                    arg->get_type(&arg_type);
                    if (!first) out += ", ";
                    out += type_name_of(arg_type, depth + 1);
                    first = false;
                }
            }
            if (first) out += "void";
            return out + ")";
        }
        default:
            return cv_prefix(type) + safe_symbol_name(type);
    }
}

// Which expensive per-symbol fields to materialize. Driven by SQLite's colUsed so a
// full scan that does not SELECT the undecorated name skips the (dominant-cost) C++
// demangle. Default = compute everything: used by the bounded name/id filter lookups
// where the per-row cost is negligible and any column may be selected.
struct SymbolProjection {
    bool undecorated = true;  // get_undecoratedName — the expensive demangle
};

// Build a full-scan projection from colUsed. undecorated_col is the 0-based index of
// the `undecorated` column in the table's schema, or -1 when the table has no such
// column (then the demangle is always skipped — it was pure waste before).
inline SymbolProjection symbol_projection_from(uint64_t col_used, int undecorated_col) {
    SymbolProjection p;
    p.undecorated = undecorated_col >= 0 &&
                    (col_used & (static_cast<uint64_t>(1) << undecorated_col)) != 0;
    return p;
}

inline CachedSymbol extract_symbol(IDiaSymbol* symbol, SymbolProjection proj = {}) {
    CachedSymbol cs;
    if (!symbol) return cs;

    symbol->get_symIndexId(&cs.id);

    SafeBSTR name;
    if (SUCCEEDED(symbol->get_name(name.ptr()))) {
        cs.name = name.str();
    }

    // The undecorated (demangled) name is by far the most expensive field; skip it
    // unless the query selects it (or a bounded lookup asks for everything).
    if (proj.undecorated) {
        SafeBSTR undec;
        if (SUCCEEDED(symbol->get_undecoratedName(undec.ptr()))) {
            cs.undecorated = undec.str();
        }
    }

    symbol->get_relativeVirtualAddress(&cs.rva);
    symbol->get_length(&cs.length);
    symbol->get_symTag(&cs.symtag);

    // A data symbol carries no length of its own -- its size is a property of its
    // TYPE, so get_length leaves 0 and `ORDER BY length` over `data` was
    // meaningless. Scoped to SymTagData so the hot functions/publics scan path
    // keeps its single get_length call. A residual 0 here is a genuine 0 (e.g. the
    // zero-length CRT section-boundary arrays __xc_a/__xc_z).
    if (cs.length == 0 && cs.symtag == SymTagData) {
        CComPtr<IDiaSymbol> type;
        if (SUCCEEDED(symbol->get_type(&type)) && type) {
            ULONGLONG type_len = 0;
            if (SUCCEEDED(type->get_length(&type_len))) cs.length = type_len;
        }
    }

    DWORD section = 0, offset = 0;
    symbol->get_addressSection(&section);
    symbol->get_addressOffset(&offset);
    cs.section = section;
    cs.offset = offset;

    return cs;
}

// Fill a udt_members row from one UDT child. `is_function` selects the member
// FUNCTION reading (virtual/pure/isStatic, no meaningful offset) over the data
// member reading (offset + type length, static via location). Shared by all three
// udt_members generators so the scan and the two pushdown paths cannot drift.
inline CachedMember extract_member(IDiaSymbol* member,
                                   bool is_function,
                                   DWORD parent_id,
                                   const std::string& parent_name) {
    CachedMember m;
    m.parent_id = parent_id;
    m.parent_name = parent_name;
    m.is_function = is_function;
    if (!member) return m;

    member->get_symIndexId(&m.id);
    m.name = safe_symbol_name(member);

    CComPtr<IDiaSymbol> type;
    if (SUCCEEDED(member->get_type(&type)) && type) {
        m.type_name = type_name_of(type);
        if (!is_function) {
            ULONGLONG len = 0;
            type->get_length(&len);
            m.length = len;
        }
    }

    DWORD access = 0;
    member->get_access(&access);
    m.access = access;

    if (is_function) {
        // Code size of the member function, when the record carries one.
        ULONGLONG len = 0;
        if (SUCCEEDED(member->get_length(&len))) m.length = len;

        BOOL flag = FALSE;
        if (SUCCEEDED(member->get_virtual(&flag)) && flag) m.is_virtual = true;
        flag = FALSE;
        if (SUCCEEDED(member->get_pure(&flag)) && flag) m.is_pure = true;
        flag = FALSE;
        if (SUCCEEDED(member->get_isStatic(&flag)) && flag) m.is_static = true;
    } else {
        LONG offset = 0;
        member->get_offset(&offset);
        m.offset = static_cast<DWORD>(offset);

        DWORD loc_type = 0;
        member->get_locationType(&loc_type);
        m.is_static = (loc_type == LocIsStatic);

        // get_virtual is never TRUE on a SymTagData child -- `virtual` is a
        // property of member FUNCTIONS. Read it anyway so the field stays faithful
        // to whatever DIA reports rather than being hardcoded.
        BOOL virt = FALSE;
        if (SUCCEEDED(member->get_virtual(&virt)) && virt) m.is_virtual = true;
    }

    return m;
}

// Human-readable SymTagEnum name for the `symbol_at.kind` column. Covers the tags
// findSymbolByRVA(SymTagNull) can return; anything else falls back to "other".
// Lowercase, snake_case -- one vocabulary for every enum-ish text column in the
// schema (see access_text / location_text). Mixed conventions across columns are
// a trap: an agent that learns one spelling then guesses wrong on another.
inline const char* symtag_name(DWORD tag) {
    switch (static_cast<enum SymTagEnum>(tag)) {
        case SymTagFunction:     return "function";
        case SymTagData:         return "data";
        case SymTagPublicSymbol: return "public_symbol";
        case SymTagLabel:        return "label";
        case SymTagThunk:        return "thunk";
        case SymTagBlock:        return "block";
        case SymTagUDT:          return "udt";
        case SymTagEnum:         return "enum";
        case SymTagTypedef:      return "typedef";
        default:                 return "other";
    }
}

inline CachedCompiland extract_compiland(IDiaSymbol* symbol) {
    CachedCompiland cc;
    if (!symbol) return cc;

    symbol->get_symIndexId(&cc.id);

    SafeBSTR name;
    if (SUCCEEDED(symbol->get_name(name.ptr()))) {
        cc.name = name.str();
    }

    SafeBSTR lib;
    if (SUCCEEDED(symbol->get_libraryName(lib.ptr()))) {
        cc.library_name = lib.str();
    }

    // `language` is a property of the compiland's SymTagCompilandDetails CHILD, not
    // of the compiland symbol. Asking the compiland directly returns S_FALSE and
    // leaves the out-param untouched -- which read as language 0 ("C") for every
    // compiland of even a pure C++ program. Note the S_OK (not SUCCEEDED) test:
    // S_FALSE passes SUCCEEDED but writes nothing, which is exactly how the old
    // code silently produced a constant.
    CComPtr<IDiaEnumSymbols> details;
    if (SUCCEEDED(symbol->findChildren(SymTagCompilandDetails, nullptr, nsNone, &details)) && details) {
        CComPtr<IDiaSymbol> detail;
        ULONG fetched = 0;
        if (SUCCEEDED(details->Next(1, &detail, &fetched)) && fetched == 1 && detail) {
            DWORD lang = 0;
            if (detail->get_language(&lang) == S_OK) {
                cc.language = lang;
                cc.has_language = true;
            }
        }
    }

    return cc;
}

inline CachedSourceFile extract_source_file(IDiaSourceFile* file) {
    CachedSourceFile sf;
    if (!file) return sf;

    file->get_uniqueId(&sf.id);

    SafeBSTR filename;
    if (SUCCEEDED(file->get_fileName(filename.ptr()))) {
        sf.filename = filename.str();
    }

    file->get_checksumType(&sf.checksum_type);
    return sf;
}

class SymbolGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    enum SymTagEnum tag_;
    SymbolProjection proj_;
    CComPtr<IDiaEnumSymbols> symbols_;
    CachedSymbol current_;
    int64_t rowid_ = -1;
    bool started_ = false;

public:
    SymbolGenerator(PdbSession& session, enum SymTagEnum tag, SymbolProjection proj = {})
        : session_(session), tag_(tag), proj_(proj) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            symbols_ = session_.enum_symbols(tag_);
        }
        if (!symbols_) return false;

        CComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;
        if (FAILED(symbols_->Next(1, &symbol, &fetched)) || fetched != 1) {
            return false;
        }

        current_ = extract_symbol(symbol, proj_);
        ++rowid_;
        return true;
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// ============================================================================
// DIA enum codes -> text
// ============================================================================
//
// These columns used to expose the raw CV_* integer, which forced every consumer
// to carry a decode table. That is a real source of bugs, not just friction: the
// documented `CASE language WHEN NULL THEN ...` decode silently never matched,
// because the simple CASE form compares with `=` and NULL = NULL is never true.
// Text values are self-describing and directly filterable.

// CV_access_e
inline std::string access_text(DWORD access) {
    switch (access) {
        case CV_private:   return "private";
        case CV_protected: return "protected";
        case CV_public:    return "public";
        default:           return "";
    }
}

// LocationType (cvconst.h). Named for what an agent would ask about.
inline std::string location_text(DWORD loc) {
    switch (loc) {
        case LocIsStatic:            return "static";
        case LocIsTLS:               return "tls";
        case LocIsRegRel:            return "regrel";
        case LocIsThisRel:           return "thisrel";
        case LocIsEnregistered:      return "register";
        case LocIsBitField:          return "bitfield";
        case LocIsSlot:              return "slot";
        case LocIsIlRel:             return "ilrel";
        case LocInMetaData:          return "metadata";
        case LocIsConstant:          return "constant";
        case LocIsNull:              return "";
        default:                     return "";
    }
}

// CV_SourceChksum_t
inline std::string checksum_text(DWORD kind) {
    switch (kind) {
        case CHKSUM_TYPE_NONE:    return "none";
        case CHKSUM_TYPE_MD5:     return "md5";
        case CHKSUM_TYPE_SHA1:    return "sha1";
        case CHKSUM_TYPE_SHA_256: return "sha256";
        default:                  return "";
    }
}

// CV_CFL_LANG. Returns "" for an unrecognized code so the caller can decide
// between NULL and a passthrough.
inline std::string language_text(DWORD lang) {
    switch (lang) {
        case CV_CFL_C:       return "C";
        case CV_CFL_CXX:     return "C++";
        case CV_CFL_FORTRAN: return "Fortran";
        case CV_CFL_MASM:    return "MASM";
        case CV_CFL_PASCAL:  return "Pascal";
        case CV_CFL_BASIC:   return "Basic";
        case CV_CFL_COBOL:   return "COBOL";
        case CV_CFL_LINK:    return "LINK";
        case CV_CFL_CVTRES:  return "CVTRES";
        case CV_CFL_CVTPGD:  return "CVTPGD";
        case CV_CFL_CSHARP:  return "C#";
        case CV_CFL_VB:      return "VB";
        case CV_CFL_ILASM:   return "ILASM";
        case CV_CFL_JAVA:    return "Java";
        case CV_CFL_JSCRIPT: return "JScript";
        case CV_CFL_MSIL:    return "MSIL";
        case CV_CFL_HLSL:    return "HLSL";
        default:             return "";
    }
}

// Names DIA emits for types that have no name of their own. These are display
// PLACEHOLDERS, not identifiers: dozens of unrelated types share one, and they
// cannot be resolved through DIA's name index at all (a `WHERE name = X` lookup
// finds nothing while a scan returns every anonymous type). Reporting them as
// SQL NULL is what makes the two paths agree; grouping by them would also merge
// types that have nothing to do with each other.
inline bool is_placeholder_type_name(const std::string& name) {
    return name.empty() || name == "<unnamed-tag>" || name == "<anonymous-tag>";
}

// One row per DISTINCT type name, streaming.
//
// DIA emits a type record per compiland that defines the type, so a raw
// enumeration repeats names — on a large PDB, 1.75M records collapse to 1.23M
// distinct names. That made the naive `SELECT ... FROM udts ORDER BY length DESC
// LIMIT 10` return a half-duplicate top-N, and it made `WHERE name = X` (which
// resolves DIA's single canonical record) disagree with a scan.
//
// Dedup is STREAMING on purpose: the set only remembers what has already been
// passed, so a LIMIT stays cheap and never pays for the whole table. Per-name
// aggregates (how many compilands define a type, the max length across records)
// deliberately live on the *_records tables instead — computing them here would
// require draining the entire enumeration before emitting the first row.
//
// Anonymous types are never deduplicated: each record is its own type and only
// shares a placeholder label.
class DedupedSymbolGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    enum SymTagEnum tag_;
    SymbolProjection proj_;
    CComPtr<IDiaEnumSymbols> symbols_;
    std::unordered_set<std::string> seen_;
    CachedSymbol current_;
    int64_t rowid_ = -1;
    bool started_ = false;

public:
    DedupedSymbolGenerator(PdbSession& session, enum SymTagEnum tag, SymbolProjection proj = {})
        : session_(session), tag_(tag), proj_(proj) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            symbols_ = session_.enum_symbols(tag_);
        }
        if (!symbols_) return false;

        for (;;) {
            CComPtr<IDiaSymbol> symbol;
            ULONG fetched = 0;
            if (FAILED(symbols_->Next(1, &symbol, &fetched)) || fetched != 1) return false;

            CachedSymbol cs = extract_symbol(symbol, proj_);
            // Anonymous types pass through un-deduplicated -- each record is its
            // own type. The column getter renders the placeholder as NULL.
            if (is_placeholder_type_name(cs.name)) {
                current_ = std::move(cs);
                ++rowid_;
                return true;
            }
            if (!seen_.insert(cs.name).second) continue;  // already emitted this type
            current_ = std::move(cs);
            ++rowid_;
            return true;
        }
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// Streams symbols that are NOT children of the global scope.
//
// DIA nests some symbol kinds under a parent: thunks hang off their compiland and
// labels off their function. Enumerating them from the global scope -- the way
// every other symbol table here is enumerated -- silently yields nothing, which is
// why `thunks` and `labels` used to return 0 rows on every PDB, including ones
// demonstrably full of both. Walks parents lazily, one child list at a time.
class NestedSymbolGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    enum SymTagEnum parent_tag_;
    enum SymTagEnum child_tag_;
    SymbolProjection proj_;

    CComPtr<IDiaEnumSymbols> parents_;
    CComPtr<IDiaEnumSymbols> children_;
    CachedSymbol current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_parent() {
        children_.Release();
        CComPtr<IDiaSymbol> parent;
        ULONG fetched = 0;
        while (SUCCEEDED(parents_->Next(1, &parent, &fetched)) && fetched == 1) {
            if (SUCCEEDED(parent->findChildren(child_tag_, nullptr, nsNone, &children_)) && children_) {
                return true;
            }
            parent.Release();
        }
        return false;
    }

public:
    NestedSymbolGenerator(PdbSession& session,
                          enum SymTagEnum parent_tag,
                          enum SymTagEnum child_tag,
                          SymbolProjection proj = {})
        : session_(session), parent_tag_(parent_tag), child_tag_(child_tag), proj_(proj) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            parents_ = session_.enum_symbols(parent_tag_);
            if (!parents_) return false;
            if (!advance_parent()) return false;
        }

        while (true) {
            if (!children_) {
                if (!advance_parent()) return false;
            }

            CComPtr<IDiaSymbol> child;
            ULONG fetched = 0;
            if (FAILED(children_->Next(1, &child, &fetched)) || fetched != 1) {
                children_.Release();
                continue;
            }

            current_ = extract_symbol(child, proj_);
            ++rowid_;
            return true;
        }
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class CompilandGenerator : public xsql::Generator<CachedCompiland> {
    PdbSession& session_;
    CComPtr<IDiaEnumSymbols> compilands_;
    CachedCompiland current_;
    int64_t rowid_ = -1;
    bool started_ = false;

public:
    explicit CompilandGenerator(PdbSession& session) : session_(session) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            compilands_ = session_.enum_symbols(SymTagCompiland);
        }
        if (!compilands_) return false;

        CComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;
        if (FAILED(compilands_->Next(1, &symbol, &fetched)) || fetched != 1) {
            return false;
        }

        current_ = extract_compiland(symbol);
        ++rowid_;
        return true;
    }

    const CachedCompiland& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class SourceFileGenerator : public xsql::Generator<CachedSourceFile> {
    PdbSession& session_;
    CComPtr<IDiaEnumSourceFiles> source_files_;
    CachedSourceFile current_;
    int64_t rowid_ = -1;
    bool started_ = false;

public:
    explicit SourceFileGenerator(PdbSession& session) : session_(session) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            IDiaSession* dia_session = session_.session();
            if (!dia_session) return false;
            if (FAILED(dia_session->findFile(nullptr, nullptr, nsNone, &source_files_))) return false;
        }
        if (!source_files_) return false;

        CComPtr<IDiaSourceFile> file;
        ULONG fetched = 0;
        if (FAILED(source_files_->Next(1, &file, &fetched)) || fetched != 1) {
            return false;
        }

        current_ = extract_source_file(file);
        ++rowid_;
        return true;
    }

    const CachedSourceFile& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class LineNumberGenerator : public xsql::Generator<CachedLineNumber> {
    PdbSession& session_;
    CComPtr<IDiaSession> dia_session_;

    CComPtr<IDiaEnumSymbols> compilands_;
    CComPtr<IDiaSymbol> current_compiland_;
    DWORD current_compiland_id_ = 0;

    CComPtr<IDiaEnumSourceFiles> source_files_;
    CComPtr<IDiaEnumLineNumbers> lines_;

    CachedLineNumber current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_compiland() {
        if (!compilands_) return false;

        current_compiland_.Release();
        current_compiland_id_ = 0;
        source_files_.Release();
        lines_.Release();

        CComPtr<IDiaSymbol> compiland;
        ULONG fetched = 0;
        while (SUCCEEDED(compilands_->Next(1, &compiland, &fetched)) && fetched == 1) {
            current_compiland_ = compiland;
            current_compiland_->get_symIndexId(&current_compiland_id_);

            if (SUCCEEDED(dia_session_->findFile(current_compiland_, nullptr, nsNone, &source_files_)) && source_files_) {
                return true;
            }

            compiland.Release();
            current_compiland_.Release();
            current_compiland_id_ = 0;
        }

        return false;
    }

    bool advance_file() {
        if (!source_files_) return false;

        lines_.Release();

        CComPtr<IDiaSourceFile> file;
        ULONG fetched = 0;
        while (SUCCEEDED(source_files_->Next(1, &file, &fetched)) && fetched == 1) {
            if (SUCCEEDED(dia_session_->findLines(current_compiland_, file, &lines_)) && lines_) {
                return true;
            }
            file.Release();
        }

        source_files_.Release();
        return false;
    }

public:
    explicit LineNumberGenerator(PdbSession& session) : session_(session) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            dia_session_ = session_.session();
            if (!dia_session_) return false;
            compilands_ = session_.enum_symbols(SymTagCompiland);
            if (!compilands_) return false;
            if (!advance_compiland()) return false;
        }

        while (true) {
            if (!lines_) {
                if (!advance_file()) {
                    if (!advance_compiland()) {
                        return false;
                    }
                    continue;
                }
            }

            CComPtr<IDiaLineNumber> line;
            ULONG fetched = 0;
            if (FAILED(lines_->Next(1, &line, &fetched)) || fetched != 1) {
                lines_.Release();
                continue;
            }

            current_ = {};
            line->get_sourceFileId(&current_.file_id);
            line->get_lineNumber(&current_.line);
            line->get_columnNumber(&current_.column);
            line->get_relativeVirtualAddress(&current_.rva);
            line->get_length(&current_.length);
            current_.compiland_id = current_compiland_id_;
            ++rowid_;
            return true;
        }
    }

    const CachedLineNumber& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class SectionGenerator : public xsql::Generator<CachedSection> {
    PdbSession& session_;
    std::vector<CachedSection> sections_;
    size_t idx_ = 0;
    int64_t rowid_ = -1;
    bool started_ = false;

    void build() {
        sections_.clear();

        IDiaSession* dia_session = session_.session();
        if (!dia_session) return;

        // Real PE sections come from the DIA "SECTIONHEADERS" debug stream (each
        // record is an IMAGE_SECTION_HEADER), NOT from SectionContribs. Optimized
        // Unreal Engine PDBs carry section headers but no SectionContribs stream,
        // so the old approach returned 0 rows. Section
        // *names* (.text/.data/…) also only exist here. Fall back to the
        // pre-incremental-link "SECTIONHEADERSORIG" stream when the primary is
        // absent.
        CComPtr<IDiaEnumDebugStreams> streams;
        if (FAILED(dia_session->getEnumDebugStreams(&streams)) || !streams) return;

        CComPtr<IDiaEnumDebugStreamData> chosen;
        CComPtr<IDiaEnumDebugStreamData> fallback;
        CComPtr<IDiaEnumDebugStreamData> stream;
        ULONG sfetched = 0;
        while (SUCCEEDED(streams->Next(1, &stream, &sfetched)) && sfetched == 1) {
            SafeBSTR name;
            if (SUCCEEDED(stream->get_name(name.ptr())) && name.get()) {
                if (wcscmp(name.get(), L"SECTIONHEADERS") == 0) {
                    chosen = stream;
                } else if (wcscmp(name.get(), L"SECTIONHEADERSORIG") == 0) {
                    fallback = stream;
                }
            }
            stream.Release();
            if (chosen) break;
        }
        if (!chosen) chosen = fallback;
        if (!chosen) return;

        // Each stream record is one IMAGE_SECTION_HEADER (40 bytes).
        DWORD ordinal = 0;
        for (;;) {
            IMAGE_SECTION_HEADER hdr{};
            DWORD cb = 0;
            ULONG cfetched = 0;
            HRESULT hr = chosen->Next(1, sizeof(hdr), &cb,
                                      reinterpret_cast<BYTE*>(&hdr), &cfetched);
            if (FAILED(hr) || cfetched != 1 || cb < sizeof(hdr)) break;

            CachedSection cs{};
            cs.section_number = ++ordinal;  // 1-based PE section ordinal

            // IMAGE_SECTION_HEADER::Name is 8 bytes, not guaranteed NUL-terminated.
            char namebuf[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
            memcpy(namebuf, hdr.Name, IMAGE_SIZEOF_SHORT_NAME);
            cs.name = namebuf;

            cs.rva = hdr.VirtualAddress;
            cs.length = hdr.Misc.VirtualSize;
            cs.characteristics = hdr.Characteristics;
            cs.read = (hdr.Characteristics & IMAGE_SCN_MEM_READ) != 0;
            cs.write = (hdr.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            cs.execute = (hdr.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            cs.code = (hdr.Characteristics & IMAGE_SCN_CNT_CODE) != 0;
            sections_.push_back(cs);
        }
    }

public:
    explicit SectionGenerator(PdbSession& session) : session_(session) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            build();
        }

        if (idx_ >= sections_.size()) return false;
        ++rowid_;
        ++idx_;
        return true;
    }

    const CachedSection& current() const override { return sections_[idx_ - 1]; }
    int64_t rowid() const override { return rowid_; }
};

// Walks every UDT and yields one child kind -- SymTagData for `udt_fields`,
// SymTagFunction for `udt_methods`. Keeping the two as separate tables (rather
// than one table with a discriminator) is what lets every column mean something
// on every row: a field always has an offset, a method never does.
class MemberGenerator : public xsql::Generator<CachedMember> {
    PdbSession& session_;
    enum SymTagEnum child_tag_;
    CComPtr<IDiaEnumSymbols> udts_;
    DWORD current_udt_id_ = 0;
    std::string current_udt_name_;
    CComPtr<IDiaEnumSymbols> members_;

    CachedMember current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_udt() {
        current_udt_id_ = 0;
        current_udt_name_.clear();
        members_.Release();

        CComPtr<IDiaSymbol> udt;
        ULONG fetched = 0;
        while (SUCCEEDED(udts_->Next(1, &udt, &fetched)) && fetched == 1) {
            DWORD id = 0;
            udt->get_symIndexId(&id);
            std::string name = safe_symbol_name(udt);
            CComPtr<IDiaEnumSymbols> children;
            if (SUCCEEDED(udt->findChildren(child_tag_, nullptr, nsNone, &children)) && children) {
                current_udt_id_ = id;
                current_udt_name_ = std::move(name);
                members_ = children;
                return true;
            }
            udt.Release();
        }
        return false;
    }

public:
    MemberGenerator(PdbSession& session, enum SymTagEnum child_tag)
        : session_(session), child_tag_(child_tag) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            udts_ = session_.enum_symbols(SymTagUDT);
            if (!udts_) return false;
            if (!advance_udt()) return false;
        }

        while (true) {
            if (!members_) {
                if (!advance_udt()) return false;
            }

            CComPtr<IDiaSymbol> member;
            ULONG fetched = 0;
            if (FAILED(members_->Next(1, &member, &fetched)) || fetched != 1) {
                members_.Release();
                continue;
            }

            current_ = extract_member(member, child_tag_ == SymTagFunction,
                                      current_udt_id_, current_udt_name_);
            ++rowid_;
            return true;
        }
    }

    const CachedMember& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class EnumValueGenerator : public xsql::Generator<CachedEnumValue> {
    PdbSession& session_;
    CComPtr<IDiaEnumSymbols> enums_;
    CComPtr<IDiaSymbol> current_enum_;
    DWORD current_enum_id_ = 0;
    std::string current_enum_name_;
    CComPtr<IDiaEnumSymbols> values_;

    CachedEnumValue current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_enum() {
        current_enum_.Release();
        current_enum_id_ = 0;
        current_enum_name_.clear();
        values_.Release();

        CComPtr<IDiaSymbol> en;
        ULONG fetched = 0;
        while (SUCCEEDED(enums_->Next(1, &en, &fetched)) && fetched == 1) {
            current_enum_ = en;
            current_enum_->get_symIndexId(&current_enum_id_);
            current_enum_name_ = safe_symbol_name(current_enum_);

            if (SUCCEEDED(current_enum_->findChildren(SymTagData, nullptr, nsNone, &values_)) && values_) {
                return true;
            }

            en.Release();
            current_enum_.Release();
            current_enum_id_ = 0;
            current_enum_name_.clear();
        }

        return false;
    }

    static int64_t variant_to_int64(const VARIANT& v) {
        switch (v.vt) {
            case VT_I1: return v.cVal;
            case VT_I2: return v.iVal;
            case VT_I4: return v.lVal;
            case VT_I8: return v.llVal;
            case VT_UI1: return v.bVal;
            case VT_UI2: return v.uiVal;
            case VT_UI4: return v.ulVal;
            case VT_UI8: return static_cast<int64_t>(v.ullVal);
            case VT_INT: return v.intVal;
            case VT_UINT: return v.uintVal;
            default: return 0;
        }
    }

public:
    explicit EnumValueGenerator(PdbSession& session) : session_(session) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            enums_ = session_.enum_symbols(SymTagEnum);
            if (!enums_) return false;
            if (!advance_enum()) return false;
        }

        while (true) {
            if (!values_) {
                if (!advance_enum()) return false;
            }

            CComPtr<IDiaSymbol> val;
            ULONG fetched = 0;
            if (FAILED(values_->Next(1, &val, &fetched)) || fetched != 1) {
                values_.Release();
                continue;
            }

            current_ = {};
            current_.enum_id = current_enum_id_;
            current_.enum_name = current_enum_name_;

            val->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(val);

            VARIANT v = {};
            if (SUCCEEDED(val->get_value(&v))) {
                current_.value = variant_to_int64(v);
                VariantClear(&v);
            }

            ++rowid_;
            return true;
        }
    }

    const CachedEnumValue& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class BaseClassGenerator : public xsql::Generator<CachedBaseClass> {
    PdbSession& session_;
    CComPtr<IDiaEnumSymbols> udts_;
    CComPtr<IDiaSymbol> current_udt_;
    DWORD current_udt_id_ = 0;
    std::string current_udt_name_;
    CComPtr<IDiaEnumSymbols> bases_;

    CachedBaseClass current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_udt() {
        current_udt_.Release();
        current_udt_id_ = 0;
        current_udt_name_.clear();
        bases_.Release();

        CComPtr<IDiaSymbol> udt;
        ULONG fetched = 0;
        while (SUCCEEDED(udts_->Next(1, &udt, &fetched)) && fetched == 1) {
            current_udt_ = udt;
            current_udt_->get_symIndexId(&current_udt_id_);
            current_udt_name_ = safe_symbol_name(current_udt_);

            if (SUCCEEDED(current_udt_->findChildren(SymTagBaseClass, nullptr, nsNone, &bases_)) && bases_) {
                return true;
            }

            udt.Release();
            current_udt_.Release();
            current_udt_id_ = 0;
            current_udt_name_.clear();
        }

        return false;
    }

public:
    explicit BaseClassGenerator(PdbSession& session) : session_(session) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            udts_ = session_.enum_symbols(SymTagUDT);
            if (!udts_) return false;
            if (!advance_udt()) return false;
        }

        while (true) {
            if (!bases_) {
                if (!advance_udt()) return false;
            }

            CComPtr<IDiaSymbol> base;
            ULONG fetched = 0;
            if (FAILED(bases_->Next(1, &base, &fetched)) || fetched != 1) {
                bases_.Release();
                continue;
            }

            current_ = {};
            current_.derived_id = current_udt_id_;
            current_.derived_name = current_udt_name_;

            CComPtr<IDiaSymbol> base_type;
            if (SUCCEEDED(base->get_type(&base_type)) && base_type) {
                base_type->get_symIndexId(&current_.base_id);
                current_.base_name = safe_symbol_name(base_type);
            }

            LONG offset = 0;
            base->get_offset(&offset);
            current_.offset = static_cast<DWORD>(offset);

            BOOL virt = FALSE;
            base->get_virtualBaseClass(&virt);
            current_.is_virtual = (virt != FALSE);

            DWORD access = 0;
            base->get_access(&access);
            current_.access = access;

            ++rowid_;
            return true;
        }
    }

    const CachedBaseClass& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class LocalOrParamGenerator : public xsql::Generator<CachedLocal> {
    PdbSession& session_;
    DWORD want_kind_ = 0;

    CComPtr<IDiaEnumSymbols> functions_;
    CComPtr<IDiaSymbol> current_func_;
    DWORD current_func_id_ = 0;
    std::string current_func_name_;
    CComPtr<IDiaEnumSymbols> data_syms_;

    CachedLocal current_;
    int64_t rowid_ = -1;
    int64_t next_ordinal_ = 0;
    bool started_ = false;

    bool advance_func() {
        current_func_.Release();
        current_func_id_ = 0;
        current_func_name_.clear();
        data_syms_.Release();
        next_ordinal_ = 0;  // ordinal is per-function, not per-scan

        CComPtr<IDiaSymbol> func;
        ULONG fetched = 0;
        while (SUCCEEDED(functions_->Next(1, &func, &fetched)) && fetched == 1) {
            current_func_ = func;
            current_func_->get_symIndexId(&current_func_id_);
            current_func_name_ = safe_symbol_name(current_func_);

            if (SUCCEEDED(current_func_->findChildren(SymTagData, nullptr, nsNone, &data_syms_)) && data_syms_) {
                return true;
            }

            func.Release();
            current_func_.Release();
            current_func_id_ = 0;
            current_func_name_.clear();
        }
        return false;
    }

public:
    LocalOrParamGenerator(PdbSession& session, DWORD want_kind) : session_(session), want_kind_(want_kind) {}

    bool next() override {
        if (!started_) {
            started_ = true;
            functions_ = session_.enum_symbols(SymTagFunction);
            if (!functions_) return false;
            if (!advance_func()) return false;
        }

        while (true) {
            if (!data_syms_) {
                if (!advance_func()) return false;
            }

            CComPtr<IDiaSymbol> data;
            ULONG fetched = 0;
            if (FAILED(data_syms_->Next(1, &data, &fetched)) || fetched != 1) {
                data_syms_.Release();
                continue;
            }

            DWORD data_kind = 0;
            data->get_dataKind(&data_kind);
            if (data_kind != want_kind_) {
                data.Release();
                continue;
            }

            current_ = {};
            current_.func_id = current_func_id_;
            current_.func_name = current_func_name_;
            current_.ordinal = next_ordinal_++;

            data->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(data);

            CComPtr<IDiaSymbol> type;
            if (SUCCEEDED(data->get_type(&type)) && type) {
                current_.type_name = type_name_of(type);
            }

            DWORD loc_type = 0;
            data->get_locationType(&loc_type);
            current_.location_type = loc_type;

            LONG offset = 0;
            DWORD reg = 0;
            data->get_offset(&offset);
            data->get_registerId(&reg);
            if (loc_type == LocIsRegRel || loc_type == LocIsThisRel) {
                current_.frame_offset = offset;
                current_.has_frame_offset = true;
            }
            if (reg != 0) {
                current_.register_id = static_cast<int64_t>(reg);
                current_.has_register = true;
            }

            ++rowid_;
            return true;
        }
    }

    const CachedLocal& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

template<typename RowData>
class GeneratorRowIterator final : public xsql::RowIterator {
    const GeneratorTableDef<RowData>* def_ = nullptr;
    std::unique_ptr<xsql::Generator<RowData>> gen_;
    bool eof_ = true;

public:
    GeneratorRowIterator(const GeneratorTableDef<RowData>* def,
                         std::unique_ptr<xsql::Generator<RowData>> gen)
        : def_(def)
        , gen_(std::move(gen))
    {}

    bool next() override {
        if (!gen_ || !gen_->next()) {
            eof_ = true;
            return false;
        }
        eof_ = false;
        return true;
    }

    bool eof() const override { return eof_; }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (eof_ || !def_) {
            ctx.result_null();
            return;
        }

        if (col < 0 || static_cast<size_t>(col) >= def_->columns.size()) {
            ctx.result_null();
            return;
        }

        def_->columns[col].get(ctx, gen_->current());
    }

    int64_t rowid() const override {
        if (eof_ || !gen_) return 0;
        return static_cast<int64_t>(gen_->rowid());
    }
};

template<typename RowData>
inline void add_filter_eq(GeneratorTableDef<RowData>& def,
                          const char* column_name,
                          std::function<std::unique_ptr<xsql::RowIterator>(int64_t)> factory,
                          double cost = 10.0,
                          double est_rows = 10.0) {
    int col_idx = def.find_column(column_name ? column_name : "");
    if (col_idx < 0) return;
    int filter_id = static_cast<int>(def.filters.size()) + 1;
    def.filters.emplace_back(
        col_idx, filter_id, cost, est_rows,
        [factory = std::move(factory)](xsql::FunctionArg val) -> std::unique_ptr<xsql::RowIterator> {
            return factory(val.as_int64());
        });
}

template<typename RowData>
inline void add_filter_eq_text(GeneratorTableDef<RowData>& def,
                               const char* column_name,
                               std::function<std::unique_ptr<xsql::RowIterator>(const char*)> factory,
                               double cost = 10.0,
                               double est_rows = 10.0) {
    int col_idx = def.find_column(column_name ? column_name : "");
    if (col_idx < 0) return;
    int filter_id = static_cast<int>(def.filters.size()) + 1;
    def.filters.emplace_back(
        col_idx, filter_id, cost, est_rows,
        [factory = std::move(factory)](xsql::FunctionArg val) -> std::unique_ptr<xsql::RowIterator> {
            const char* text = val.as_c_str();
            return factory(text ? text : "");
        });
}

// Registers a GT/GE/LT/LE range pushdown on one column, ascending-ordered. Mirrors
// xsql::GeneratorTableBuilder::constraint_filter()+order_by_consumed(), but as a
// direct field mutation matching add_filter_eq's style, since functions_/publics_
// are already-built GeneratorTableDef instances, not live builders.
template<typename RowData>
inline void add_constraint_range_filter(
        GeneratorTableDef<RowData>& def,
        const char* column_name,
        std::function<std::unique_ptr<xsql::Generator<RowData>>(
            const std::vector<xsql::GeneratorConstraintArg>&)> factory,
        double cost = 5.0,
        double est_rows = 1000.0) {
    int col_idx = def.find_column(column_name ? column_name : "");
    if (col_idx < 0) return;
    xsql::ConstraintFilterDef<RowData> cf;
    cf.specs.push_back(xsql::GeneratorConstraintSpec{col_idx, xsql::ConstraintOp::Gt, false, ""});
    cf.specs.push_back(xsql::GeneratorConstraintSpec{col_idx, xsql::ConstraintOp::Ge, false, ""});
    cf.specs.push_back(xsql::GeneratorConstraintSpec{col_idx, xsql::ConstraintOp::Lt, false, ""});
    cf.specs.push_back(xsql::GeneratorConstraintSpec{col_idx, xsql::ConstraintOp::Le, false, ""});
    cf.filter_id = xsql::CONSTRAINT_FILTER_BASE + static_cast<int>(def.constraint_filters.size());
    cf.estimated_cost = cost;
    cf.estimated_rows = est_rows;
    cf.ordered_column = col_idx;
    cf.ordered_desc = false;
    cf.create = std::move(factory);
    def.constraint_filters.push_back(std::move(cf));
}

// Filtered generators used by constraint pushdown (xBestIndex/xFilter).

class SymbolByNameGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    enum SymTagEnum tag_;
    std::string name_;
    CComPtr<IDiaEnumSymbols> symbols_;
    CachedSymbol current_;
    int64_t rowid_ = -1;
    bool started_ = false;

public:
    SymbolByNameGenerator(PdbSession& session, enum SymTagEnum tag, std::string name)
        : session_(session)
        , tag_(tag)
        , name_(std::move(name))
    {}

    bool next() override {
        if (!started_) {
            started_ = true;
            symbols_ = session_.find_symbols(name_, tag_);
        }
        if (!symbols_) return false;

        CComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;
        if (FAILED(symbols_->Next(1, &symbol, &fetched)) || fetched != 1) {
            return false;
        }

        current_ = extract_symbol(symbol);
        ++rowid_;
        return true;
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class SymbolByIdGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    DWORD id_ = 0;
    enum SymTagEnum tag_;
    std::function<bool(IDiaSymbol*)> accept_;
    CachedSymbol current_;
    bool emitted_ = false;
    int64_t rowid_ = -1;

public:
    SymbolByIdGenerator(PdbSession& session,
                        DWORD id,
                        enum SymTagEnum tag,
                        std::function<bool(IDiaSymbol*)> accept = nullptr)
        : session_(session)
        , id_(id)
        , tag_(tag)
        , accept_(std::move(accept))
    {}

    bool next() override {
        if (emitted_) return false;
        emitted_ = true;

        IDiaSession* dia_session = session_.session();
        if (!dia_session) return false;

        CComPtr<IDiaSymbol> symbol;
        if (FAILED(dia_session->symbolById(id_, &symbol)) || !symbol) {
            return false;
        }

        DWORD got_tag = 0;
        symbol->get_symTag(&got_tag);
        if (static_cast<enum SymTagEnum>(got_tag) != tag_) {
            return false;
        }

        if (accept_ && !accept_(symbol)) {
            return false;
        }

        current_ = extract_symbol(symbol);
        rowid_ = 0;
        return true;
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// Emits the single symbol at an exact RVA via DIA's native findSymbolByRVA (a direct
// address-index lookup — no full walk, no cache). findSymbolByRVA is containment-based,
// so we confirm the exact start to honor `WHERE rva = X` (SQLite omits the recheck).
class SymbolByRvaGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    DWORD rva_ = 0;
    enum SymTagEnum tag_;
    CachedSymbol current_;
    bool emitted_ = false;
    int64_t rowid_ = -1;

public:
    SymbolByRvaGenerator(PdbSession& session, DWORD rva, enum SymTagEnum tag)
        : session_(session), rva_(rva), tag_(tag) {}

    bool next() override {
        if (emitted_) return false;
        emitted_ = true;

        CComPtr<IDiaSymbol> symbol = session_.find_symbol_by_rva(rva_, tag_);
        if (!symbol) return false;

        DWORD got_rva = 0;
        if (FAILED(symbol->get_relativeVirtualAddress(&got_rva)) || got_rva != rva_) {
            return false;  // containment hit that does not start exactly at rva_
        }

        current_ = extract_symbol(symbol);
        rowid_ = 0;
        return true;
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// Emits the single innermost symbol of ANY kind CONTAINING an address, via DIA's
// findSymbolByRVA(SymTagNull) — the engine of the `symbol_at(addr)` table-valued
// function. Unlike SymbolByRvaGenerator (exact-start `WHERE rva = X`), this KEEPS a
// containment hit. Measured DIA behavior (kb symbol-at-lab/FINDINGS.md) is
// nearest-at-or-below, so we confirm the address truly falls within
// [start, start+length) before emitting; an address in a gap yields no row.
class SymbolAtRvaGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    DWORD rva_ = 0;
    CachedSymbol current_;
    bool done_ = false;   // out-of-range address, or already decided
    int64_t rowid_ = -1;

public:
    SymbolAtRvaGenerator(PdbSession& session, int64_t addr) : session_(session) {
        if (addr < 0 || addr > 0xFFFFFFFFLL) done_ = true;  // not a valid RVA: no rows
        else rva_ = static_cast<DWORD>(addr);
    }

    bool next() override {
        if (done_) return false;
        done_ = true;

        CComPtr<IDiaSymbol> symbol = session_.find_symbol_by_rva(rva_, SymTagNull);
        if (!symbol) return false;

        DWORD got_rva = 0;
        ULONGLONG got_len = 0;
        symbol->get_relativeVirtualAddress(&got_rva);
        symbol->get_length(&got_len);
        // findSymbolByRVA is nearest-at-or-below, so verify true containment before
        // emitting — otherwise a distant nearest-below symbol (e.g. a zero-length data
        // symbol at rva 0) would be wrongly returned for an address in a gap.
        if (got_rva > rva_) return false;                       // starts after the address
        if (got_len > 0) {
            // Sized symbol: the address must fall within [start, start+length).
            if (static_cast<ULONGLONG>(rva_) >= static_cast<ULONGLONG>(got_rva) + got_len)
                return false;                                   // past the symbol's end
        } else if (got_rva != rva_) {
            return false;  // a zero-length symbol contains only its own exact address
        }

        current_ = extract_symbol(symbol);
        rowid_ = 0;
        return true;
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// Emits symbols of `tag_` whose rva falls within a bounded, half-open [start_, end_)
// range, via DIA's address-ordered enumerator: one symbolByRVA seek to `start_`, then
// a linear Next() walk that stops as soon as it passes `end_`. This is a BOUNDED-RANGE
// primitive (`WHERE rva BETWEEN a AND b`) and a reconnect/resume aid for a dropped bulk
// pull -- NOT a per-page pagination mechanism: the seek itself is not O(1)/indexed, so
// reseeking once per page is worse than one linear pull. A single bounded seek pays
// that cost once, which is fine for an actual range query or an occasional reconnect
// -- do not repurpose this for OFFSET-style paging of a whole table.
//
// The by-address stream interleaves all symbol kinds, so `tag_` is filtered here.
class SymbolRangeGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    enum SymTagEnum tag_;
    DWORD start_ = 0;              // inclusive lower bound
    DWORD end_ = 0xFFFFFFFFu;      // exclusive upper bound (only checked if has_end_)
    bool has_end_ = false;
    CComPtr<IDiaEnumSymbolsByAddr> by_addr_;
    CComPtr<IDiaSymbol> pending_;  // the symbol returned directly by the symbolByRVA seek
    CachedSymbol current_;
    int64_t rowid_ = -1;
    bool started_ = false;
    bool done_ = false;

public:
    SymbolRangeGenerator(PdbSession& session, enum SymTagEnum tag, DWORD start, DWORD end, bool has_end)
        : session_(session), tag_(tag), start_(start), end_(end), has_end_(has_end) {}

    bool next() override {
        if (done_) return false;
        if (!started_) {
            started_ = true;
            by_addr_ = session_.symbols_by_addr();
            if (!by_addr_) { done_ = true; return false; }
            by_addr_->symbolByRVA(start_, &pending_);
        }
        for (;;) {
            CComPtr<IDiaSymbol> symbol;
            if (pending_) {
                symbol = pending_;
                pending_.Release();
            } else {
                CComPtr<IDiaSymbol> next_sym;
                ULONG got = 0;
                if (FAILED(by_addr_->Next(1, &next_sym, &got)) || got != 1) { done_ = true; return false; }
                symbol = next_sym;
            }
            DWORD rva = 0, tag = 0;
            symbol->get_relativeVirtualAddress(&rva);
            symbol->get_symTag(&tag);
            if (rva < start_) continue;  // symbolByRVA seeks at-or-after start_, but be defensive
            if (has_end_ && rva >= end_) { done_ = true; return false; }  // past the upper bound: stop
            if (static_cast<enum SymTagEnum>(tag) != tag_) continue;      // wrong kind, keep walking

            current_ = extract_symbol(symbol);
            ++rowid_;
            return true;
        }
    }

    const CachedSymbol& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// Parses GT/GE/LT/LE constraint args on one rva column into a normalized half-open
// [start, end) range and builds the SymbolRangeGenerator for it. Saturates on the
// DWORD range boundary (0xFFFFFFFF) when converting an exclusive bound to inclusive
// (or vice versa).
inline std::unique_ptr<xsql::Generator<CachedSymbol>> make_symbol_range_generator(
        PdbSession& session, enum SymTagEnum tag,
        const std::vector<xsql::GeneratorConstraintArg>& args) {
    constexpr DWORD kMaxRva = 0xFFFFFFFFu;
    auto as_rva = [kMaxRva](const xsql::FunctionArg& v) -> DWORD {
        int64_t i = v.as_int64();
        if (i < 0) return 0;
        if (i > static_cast<int64_t>(kMaxRva)) return kMaxRva;
        return static_cast<DWORD>(i);
    };
    auto saturating_next = [kMaxRva](DWORD rva) { return rva >= kMaxRva ? kMaxRva : rva + 1; };

    DWORD start = 0;
    DWORD end = kMaxRva;
    bool has_end = false;
    for (const auto& arg : args) {
        const DWORD rva = as_rva(arg.value);
        switch (arg.op) {
            case xsql::ConstraintOp::Ge: start = (std::max)(start, rva); break;
            case xsql::ConstraintOp::Gt: start = (std::max)(start, saturating_next(rva)); break;
            case xsql::ConstraintOp::Le:
                end = has_end ? (std::min)(end, saturating_next(rva)) : saturating_next(rva);
                has_end = true;
                break;
            case xsql::ConstraintOp::Lt:
                end = has_end ? (std::min)(end, rva) : rva;
                has_end = true;
                break;
            default: break;
        }
    }
    return std::make_unique<SymbolRangeGenerator>(session, tag, start, end, has_end);
}

class CompilandByNameGenerator : public xsql::Generator<CachedCompiland> {
    PdbSession& session_;
    std::string name_;
    CComPtr<IDiaEnumSymbols> compilands_;
    CachedCompiland current_;
    int64_t rowid_ = -1;
    bool started_ = false;

public:
    CompilandByNameGenerator(PdbSession& session, std::string name)
        : session_(session)
        , name_(std::move(name))
    {}

    bool next() override {
        if (!started_) {
            started_ = true;
            compilands_ = session_.find_symbols(name_, SymTagCompiland);
        }
        if (!compilands_) return false;

        CComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;
        if (FAILED(compilands_->Next(1, &symbol, &fetched)) || fetched != 1) {
            return false;
        }

        current_ = extract_compiland(symbol);
        ++rowid_;
        return true;
    }

    const CachedCompiland& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class CompilandByIdGenerator : public xsql::Generator<CachedCompiland> {
    PdbSession& session_;
    DWORD id_ = 0;
    CachedCompiland current_;
    bool emitted_ = false;
    int64_t rowid_ = -1;

public:
    CompilandByIdGenerator(PdbSession& session, DWORD id)
        : session_(session)
        , id_(id)
    {}

    bool next() override {
        if (emitted_) return false;
        emitted_ = true;

        IDiaSession* dia_session = session_.session();
        if (!dia_session) return false;

        CComPtr<IDiaSymbol> symbol;
        if (FAILED(dia_session->symbolById(id_, &symbol)) || !symbol) {
            return false;
        }

        DWORD tag = 0;
        symbol->get_symTag(&tag);
        if (static_cast<enum SymTagEnum>(tag) != SymTagCompiland) {
            return false;
        }

        current_ = extract_compiland(symbol);
        rowid_ = 0;
        return true;
    }

    const CachedCompiland& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class SourceFileByIdGenerator : public xsql::Generator<CachedSourceFile> {
    PdbSession& session_;
    DWORD file_id_ = 0;
    CachedSourceFile current_;
    bool emitted_ = false;
    int64_t rowid_ = -1;

public:
    SourceFileByIdGenerator(PdbSession& session, DWORD file_id)
        : session_(session)
        , file_id_(file_id)
    {}

    bool next() override {
        if (emitted_) return false;
        emitted_ = true;

        IDiaSession* dia_session = session_.session();
        if (!dia_session) return false;

        CComPtr<IDiaSourceFile> file;
        if (FAILED(dia_session->findFileById(file_id_, &file)) || !file) {
            return false;
        }

        current_ = extract_source_file(file);
        rowid_ = 0;
        return true;
    }

    const CachedSourceFile& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class UdtMembersByIdGenerator : public xsql::Generator<CachedMember> {
    PdbSession& session_;
    DWORD udt_id_ = 0;
    enum SymTagEnum child_tag_;
    bool started_ = false;
    DWORD parent_id_ = 0;
    std::string parent_name_;
    CComPtr<IDiaEnumSymbols> members_;
    CachedMember current_;
    int64_t rowid_ = -1;

public:
    UdtMembersByIdGenerator(PdbSession& session, DWORD udt_id, enum SymTagEnum child_tag)
        : session_(session)
        , udt_id_(udt_id)
        , child_tag_(child_tag)
    {}

    bool next() override {
        if (!started_) {
            started_ = true;

            IDiaSession* dia_session = session_.session();
            if (!dia_session) return false;

            CComPtr<IDiaSymbol> udt;
            if (FAILED(dia_session->symbolById(udt_id_, &udt)) || !udt) return false;

            DWORD tag = 0;
            udt->get_symTag(&tag);
            if (static_cast<enum SymTagEnum>(tag) != SymTagUDT) return false;

            parent_id_ = udt_id_;
            parent_name_ = safe_symbol_name(udt);
            if (FAILED(udt->findChildren(child_tag_, nullptr, nsNone, &members_))) {
                members_.Release();
            }
        }

        if (!members_) return false;

        while (true) {
            CComPtr<IDiaSymbol> member;
            ULONG fetched = 0;
            if (FAILED(members_->Next(1, &member, &fetched)) || fetched != 1) return false;

            current_ = extract_member(member, child_tag_ == SymTagFunction,
                                      parent_id_, parent_name_);
            ++rowid_;
            return true;
        }
    }

    const CachedMember& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class UdtMembersByNameGenerator : public xsql::Generator<CachedMember> {
    PdbSession& session_;
    std::string udt_name_;

    enum SymTagEnum child_tag_;
    CComPtr<IDiaEnumSymbols> udts_;
    DWORD parent_id_ = 0;
    std::string parent_name_;
    CComPtr<IDiaEnumSymbols> members_;

    CachedMember current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_udt() {
        parent_id_ = 0;
        parent_name_.clear();
        members_.Release();

        CComPtr<IDiaSymbol> udt;
        ULONG fetched = 0;
        while (SUCCEEDED(udts_->Next(1, &udt, &fetched)) && fetched == 1) {
            DWORD id = 0;
            udt->get_symIndexId(&id);
            std::string name = safe_symbol_name(udt);
            CComPtr<IDiaEnumSymbols> children;
            if (SUCCEEDED(udt->findChildren(child_tag_, nullptr, nsNone, &children)) && children) {
                parent_id_ = id;
                parent_name_ = std::move(name);
                members_ = children;
                return true;
            }
            udt.Release();
        }
        return false;
    }

public:
    UdtMembersByNameGenerator(PdbSession& session, std::string udt_name, enum SymTagEnum child_tag)
        : session_(session)
        , udt_name_(std::move(udt_name))
        , child_tag_(child_tag)
    {}

    bool next() override {
        if (!started_) {
            started_ = true;
            udts_ = session_.find_symbols(udt_name_, SymTagUDT);
            if (!udts_) return false;
            if (!advance_udt()) return false;
        }

        while (true) {
            if (!members_) {
                if (!advance_udt()) return false;
            }

            CComPtr<IDiaSymbol> member;
            ULONG fetched = 0;
            if (FAILED(members_->Next(1, &member, &fetched)) || fetched != 1) {
                members_.Release();
                continue;
            }

            current_ = extract_member(member, child_tag_ == SymTagFunction,
                                      parent_id_, parent_name_);
            ++rowid_;
            return true;
        }
    }

    const CachedMember& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class EnumValuesByIdGenerator : public xsql::Generator<CachedEnumValue> {
    PdbSession& session_;
    DWORD enum_id_ = 0;
    bool started_ = false;
    std::string enum_name_;
    CComPtr<IDiaEnumSymbols> values_;
    CachedEnumValue current_;
    int64_t rowid_ = -1;

    static int64_t variant_to_int64(const VARIANT& v) {
        switch (v.vt) {
            case VT_I1: return v.cVal;
            case VT_I2: return v.iVal;
            case VT_I4: return v.lVal;
            case VT_I8: return v.llVal;
            case VT_UI1: return v.bVal;
            case VT_UI2: return v.uiVal;
            case VT_UI4: return v.ulVal;
            case VT_UI8: return static_cast<int64_t>(v.ullVal);
            case VT_INT: return v.intVal;
            case VT_UINT: return v.uintVal;
            default: return 0;
        }
    }

public:
    EnumValuesByIdGenerator(PdbSession& session, DWORD enum_id)
        : session_(session)
        , enum_id_(enum_id)
    {}

    bool next() override {
        if (!started_) {
            started_ = true;

            IDiaSession* dia_session = session_.session();
            if (!dia_session) return false;

            CComPtr<IDiaSymbol> en;
            if (FAILED(dia_session->symbolById(enum_id_, &en)) || !en) return false;

            DWORD tag = 0;
            en->get_symTag(&tag);
            if (static_cast<enum SymTagEnum>(tag) != SymTagEnum) return false;

            enum_name_ = safe_symbol_name(en);
            if (FAILED(en->findChildren(SymTagData, nullptr, nsNone, &values_)) || !values_) return false;
        }

        while (true) {
            CComPtr<IDiaSymbol> val;
            ULONG fetched = 0;
            if (FAILED(values_->Next(1, &val, &fetched)) || fetched != 1) {
                return false;
            }

            current_ = {};
            current_.enum_id = enum_id_;
            current_.enum_name = enum_name_;
            val->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(val);

            VARIANT v = {};
            if (SUCCEEDED(val->get_value(&v))) {
                current_.value = variant_to_int64(v);
                VariantClear(&v);
            }

            ++rowid_;
            return true;
        }
    }

    const CachedEnumValue& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class EnumValuesByNameGenerator : public xsql::Generator<CachedEnumValue> {
    PdbSession& session_;
    std::string enum_name_;

    CComPtr<IDiaEnumSymbols> enums_;
    CComPtr<IDiaSymbol> current_enum_;
    DWORD current_enum_id_ = 0;
    std::string current_enum_name_;
    CComPtr<IDiaEnumSymbols> values_;

    CachedEnumValue current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_enum() {
        current_enum_.Release();
        current_enum_id_ = 0;
        current_enum_name_.clear();
        values_.Release();

        CComPtr<IDiaSymbol> en;
        ULONG fetched = 0;
        while (SUCCEEDED(enums_->Next(1, &en, &fetched)) && fetched == 1) {
            current_enum_ = en;
            current_enum_->get_symIndexId(&current_enum_id_);
            current_enum_name_ = safe_symbol_name(current_enum_);
            if (SUCCEEDED(current_enum_->findChildren(SymTagData, nullptr, nsNone, &values_)) && values_) {
                return true;
            }
            en.Release();
            current_enum_.Release();
            current_enum_id_ = 0;
            current_enum_name_.clear();
        }

        return false;
    }

    static int64_t variant_to_int64(const VARIANT& v) {
        switch (v.vt) {
            case VT_I1: return v.cVal;
            case VT_I2: return v.iVal;
            case VT_I4: return v.lVal;
            case VT_I8: return v.llVal;
            case VT_UI1: return v.bVal;
            case VT_UI2: return v.uiVal;
            case VT_UI4: return v.ulVal;
            case VT_UI8: return static_cast<int64_t>(v.ullVal);
            case VT_INT: return v.intVal;
            case VT_UINT: return v.uintVal;
            default: return 0;
        }
    }

public:
    EnumValuesByNameGenerator(PdbSession& session, std::string enum_name)
        : session_(session)
        , enum_name_(std::move(enum_name))
    {}

    bool next() override {
        if (!started_) {
            started_ = true;
            enums_ = session_.find_symbols(enum_name_, SymTagEnum);
            if (!enums_) return false;
            if (!advance_enum()) return false;
        }

        while (true) {
            if (!values_) {
                if (!advance_enum()) return false;
            }

            CComPtr<IDiaSymbol> val;
            ULONG fetched = 0;
            if (FAILED(values_->Next(1, &val, &fetched)) || fetched != 1) {
                values_.Release();
                continue;
            }

            current_ = {};
            current_.enum_id = current_enum_id_;
            current_.enum_name = current_enum_name_;

            val->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(val);

            VARIANT v = {};
            if (SUCCEEDED(val->get_value(&v))) {
                current_.value = variant_to_int64(v);
                VariantClear(&v);
            }

            ++rowid_;
            return true;
        }
    }

    const CachedEnumValue& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// Fill a base_classes row from one SymTagBaseClass child of `derived`.
inline CachedBaseClass extract_base_class(IDiaSymbol* base,
                                          DWORD derived_id,
                                          const std::string& derived_name) {
    CachedBaseClass bc;
    bc.derived_id = derived_id;
    bc.derived_name = derived_name;
    if (!base) return bc;

    CComPtr<IDiaSymbol> base_type;
    if (SUCCEEDED(base->get_type(&base_type)) && base_type) {
        base_type->get_symIndexId(&bc.base_id);
        bc.base_name = safe_symbol_name(base_type);
    }

    LONG offset = 0;
    base->get_offset(&offset);
    bc.offset = static_cast<DWORD>(offset);

    BOOL virt = FALSE;
    base->get_virtualBaseClass(&virt);
    bc.is_virtual = (virt != FALSE);

    DWORD access = 0;
    base->get_access(&access);
    bc.access = access;
    return bc;
}

// `WHERE derived_name = X` -- resolve the UDT(s) by name, then read their
// SymTagBaseClass children.
//
// This is the child -> parent direction, the only one DIA indexes: a derived class
// records its bases, and nothing records a base's subclasses. So an UPWARD walk
// (a class to its ancestors) is index-backed here, while the downward walk
// (`WHERE base_name = X` -> all subclasses) still costs a full scan per step.
// Name lookup can match several UDT records because DIA emits one per defining
// compiland, so every match is walked.
class BaseClassesByDerivedNameGenerator : public xsql::Generator<CachedBaseClass> {
    PdbSession& session_;
    std::string derived_name_;

    CComPtr<IDiaEnumSymbols> udts_;
    CComPtr<IDiaSymbol> current_udt_;
    DWORD derived_id_ = 0;
    std::string resolved_name_;
    CComPtr<IDiaEnumSymbols> bases_;

    CachedBaseClass current_;
    int64_t rowid_ = -1;
    bool started_ = false;

    bool advance_udt() {
        current_udt_.Release();
        derived_id_ = 0;
        resolved_name_.clear();
        bases_.Release();

        CComPtr<IDiaSymbol> udt;
        ULONG fetched = 0;
        while (SUCCEEDED(udts_->Next(1, &udt, &fetched)) && fetched == 1) {
            current_udt_ = udt;
            current_udt_->get_symIndexId(&derived_id_);
            resolved_name_ = safe_symbol_name(current_udt_);
            if (SUCCEEDED(current_udt_->findChildren(SymTagBaseClass, nullptr, nsNone, &bases_)) && bases_) {
                return true;
            }
            udt.Release();
            current_udt_.Release();
            derived_id_ = 0;
            resolved_name_.clear();
        }
        return false;
    }

public:
    BaseClassesByDerivedNameGenerator(PdbSession& session, std::string derived_name)
        : session_(session)
        , derived_name_(std::move(derived_name))
    {}

    bool next() override {
        if (!started_) {
            started_ = true;
            udts_ = session_.find_symbols(derived_name_, SymTagUDT);
            if (!udts_) return false;
            if (!advance_udt()) return false;
        }

        while (true) {
            if (!bases_) {
                if (!advance_udt()) return false;
            }

            CComPtr<IDiaSymbol> base;
            ULONG fetched = 0;
            if (FAILED(bases_->Next(1, &base, &fetched)) || fetched != 1) {
                bases_.Release();
                continue;
            }

            current_ = extract_base_class(base, derived_id_, resolved_name_);
            ++rowid_;
            return true;
        }
    }

    const CachedBaseClass& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class BaseClassesByDerivedIdGenerator : public xsql::Generator<CachedBaseClass> {
    PdbSession& session_;
    DWORD derived_id_ = 0;
    bool started_ = false;
    std::string derived_name_;
    CComPtr<IDiaEnumSymbols> bases_;
    CachedBaseClass current_;
    int64_t rowid_ = -1;

public:
    BaseClassesByDerivedIdGenerator(PdbSession& session, DWORD derived_id)
        : session_(session)
        , derived_id_(derived_id)
    {}

    bool next() override {
        if (!started_) {
            started_ = true;

            IDiaSession* dia_session = session_.session();
            if (!dia_session) return false;

            CComPtr<IDiaSymbol> udt;
            if (FAILED(dia_session->symbolById(derived_id_, &udt)) || !udt) return false;

            DWORD tag = 0;
            udt->get_symTag(&tag);
            if (static_cast<enum SymTagEnum>(tag) != SymTagUDT) return false;

            derived_name_ = safe_symbol_name(udt);
            if (FAILED(udt->findChildren(SymTagBaseClass, nullptr, nsNone, &bases_)) || !bases_) return false;
        }

        while (true) {
            CComPtr<IDiaSymbol> base;
            ULONG fetched = 0;
            if (FAILED(bases_->Next(1, &base, &fetched)) || fetched != 1) {
                return false;
            }

            current_ = extract_base_class(base, derived_id_, derived_name_);
            ++rowid_;
            return true;
        }
    }

    const CachedBaseClass& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class LocalOrParamByFuncIdGenerator : public xsql::Generator<CachedLocal> {
    PdbSession& session_;
    DWORD func_id_ = 0;
    DWORD want_kind_ = 0;
    bool started_ = false;
    std::string func_name_;
    CComPtr<IDiaEnumSymbols> data_syms_;
    CachedLocal current_;
    int64_t rowid_ = -1;
    int64_t next_ordinal_ = 0;

public:
    LocalOrParamByFuncIdGenerator(PdbSession& session, DWORD func_id, DWORD want_kind)
        : session_(session)
        , func_id_(func_id)
        , want_kind_(want_kind)
    {}

    bool next() override {
        if (!started_) {
            started_ = true;

            IDiaSession* dia_session = session_.session();
            if (!dia_session) return false;

            CComPtr<IDiaSymbol> func;
            if (FAILED(dia_session->symbolById(func_id_, &func)) || !func) return false;

            DWORD tag = 0;
            func->get_symTag(&tag);
            if (static_cast<enum SymTagEnum>(tag) != SymTagFunction) return false;

            func_name_ = safe_symbol_name(func);
            if (FAILED(func->findChildren(SymTagData, nullptr, nsNone, &data_syms_)) || !data_syms_) return false;
        }

        while (true) {
            CComPtr<IDiaSymbol> data;
            ULONG fetched = 0;
            if (FAILED(data_syms_->Next(1, &data, &fetched)) || fetched != 1) {
                return false;
            }

            DWORD data_kind = 0;
            data->get_dataKind(&data_kind);
            if (data_kind != want_kind_) {
                data.Release();
                continue;
            }

            current_ = {};
            current_.func_id = func_id_;
            current_.func_name = func_name_;
            current_.ordinal = next_ordinal_++;
            data->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(data);

            CComPtr<IDiaSymbol> type;
            if (SUCCEEDED(data->get_type(&type)) && type) {
                current_.type_name = type_name_of(type);
            }

            DWORD loc_type = 0;
            data->get_locationType(&loc_type);
            current_.location_type = loc_type;

            LONG offset = 0;
            DWORD reg = 0;
            data->get_offset(&offset);
            data->get_registerId(&reg);
            if (loc_type == LocIsRegRel || loc_type == LocIsThisRel) {
                current_.frame_offset = offset;
                current_.has_frame_offset = true;
            }
            if (reg != 0) {
                current_.register_id = static_cast<int64_t>(reg);
                current_.has_register = true;
            }

            ++rowid_;
            return true;
        }
    }

    const CachedLocal& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

class LineNumbersByCompilandIdGenerator : public xsql::Generator<CachedLineNumber> {
    PdbSession& session_;
    DWORD compiland_id_ = 0;
    bool started_ = false;
    CComPtr<IDiaSession> dia_session_;
    CComPtr<IDiaSymbol> compiland_;
    CComPtr<IDiaEnumSourceFiles> source_files_;
    CComPtr<IDiaEnumLineNumbers> lines_;
    CachedLineNumber current_;
    int64_t rowid_ = -1;

    bool advance_file() {
        if (!source_files_) return false;

        lines_.Release();

        CComPtr<IDiaSourceFile> file;
        ULONG fetched = 0;
        while (SUCCEEDED(source_files_->Next(1, &file, &fetched)) && fetched == 1) {
            if (SUCCEEDED(dia_session_->findLines(compiland_, file, &lines_)) && lines_) {
                return true;
            }
            file.Release();
        }

        source_files_.Release();
        return false;
    }

public:
    LineNumbersByCompilandIdGenerator(PdbSession& session, DWORD compiland_id)
        : session_(session)
        , compiland_id_(compiland_id)
    {}

    bool next() override {
        if (!started_) {
            started_ = true;

            dia_session_ = session_.session();
            if (!dia_session_) return false;

            if (FAILED(dia_session_->symbolById(compiland_id_, &compiland_)) || !compiland_) return false;

            DWORD tag = 0;
            compiland_->get_symTag(&tag);
            if (static_cast<enum SymTagEnum>(tag) != SymTagCompiland) return false;

            if (FAILED(dia_session_->findFile(compiland_, nullptr, nsNone, &source_files_)) || !source_files_) return false;
        }

        while (true) {
            if (!lines_) {
                if (!advance_file()) return false;
            }

            CComPtr<IDiaLineNumber> line;
            ULONG fetched = 0;
            if (FAILED(lines_->Next(1, &line, &fetched)) || fetched != 1) {
                lines_.Release();
                continue;
            }

            current_ = {};
            line->get_sourceFileId(&current_.file_id);
            line->get_lineNumber(&current_.line);
            line->get_columnNumber(&current_.column);
            line->get_relativeVirtualAddress(&current_.rva);
            line->get_length(&current_.length);
            current_.compiland_id = compiland_id_;
            ++rowid_;
            return true;
        }
    }

    const CachedLineNumber& current() const override { return current_; }
    int64_t rowid() const override { return rowid_; }
};

// ============================================================================
// Table Definitions
// ============================================================================

// Functions table
inline GeneratorTableDef<CachedSymbol> define_functions_table(PdbSession& session) {
    return generator_table<CachedSymbol>("functions")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .row_count([&session]() { return to_size_t_clamped(session.count_symbols(SymTagFunction)); })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<SymbolGenerator>(session, SymTagFunction, symbol_projection_from(col_used, 2)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_text("undecorated", [](const CachedSymbol& r) { return r.undecorated; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        .build();
}

// symbol_at(addr) — table-valued function returning the innermost symbol of ANY kind
// CONTAINING an address, via DIA's findSymbolByRVA (cache-free, O(1)). `addr` is a
// HIDDEN argument, so both the SQLite TVF sugar `SELECT ... FROM symbol_at(0x1234)`
// and `... FROM symbol_at WHERE addr = 0x1234` work; it returns 0 or 1 row. The `kind`
// column names the SymTag; `rva`/`length` describe the matched symbol (its start may
// be <= addr).
inline GeneratorTableDef<CachedSymbol> define_symbol_at_table(PdbSession& session) {
    return generator_table<CachedSymbol>("symbol_at")
        .estimate_rows([]() { return static_cast<size_t>(1); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_text("undecorated", [](const CachedSymbol& r) { return r.undecorated; })
        .column_text("kind", [](const CachedSymbol& r) { return std::string(symtag_name(r.symtag)); })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        // Hidden input bound by the positional TVF arg or a WHERE predicate. `rva`
        // above is the matched symbol's start (may be <= addr); `addr` is the query.
        .hidden_column_int64("addr")
        .parametric_filter({"addr"},
            [&session](const std::vector<xsql::FunctionArg>& args)
                -> std::unique_ptr<xsql::Generator<CachedSymbol>> {
                const int64_t addr = args.empty() ? -1 : args[0].as_int64();
                return std::make_unique<SymbolAtRvaGenerator>(session, addr);
            },
            1.0, 1.0)
        .full_scan_error("symbol_at requires an address: SELECT * FROM symbol_at(0x1234) "
                         "or SELECT * FROM symbol_at WHERE addr = 0x1234")
        .build();
}

// Public symbols table
inline GeneratorTableDef<CachedSymbol> define_publics_table(PdbSession& session) {
    return generator_table<CachedSymbol>("publics")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .row_count([&session]() { return to_size_t_clamped(session.count_symbols(SymTagPublicSymbol)); })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<SymbolGenerator>(session, SymTagPublicSymbol, symbol_projection_from(col_used, 2)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_text("undecorated", [](const CachedSymbol& r) { return r.undecorated; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        .build();
}

// Data symbols table
inline GeneratorTableDef<CachedSymbol> define_data_table(PdbSession& session) {
    return generator_table<CachedSymbol>("data")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .row_count([&session]() { return to_size_t_clamped(session.count_symbols(SymTagData)); })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<SymbolGenerator>(session, SymTagData, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        .build();
}

// UDT (structs/classes) table
// A type name is NULL for anonymous types (see is_placeholder_type_name). This
// lives on the COLUMN, not the generator, so the deduplicated table and its
// *_records twin cannot disagree about what an anonymous type is called.
inline std::optional<std::string> type_name_or_null(const CachedSymbol& r) {
    if (is_placeholder_type_name(r.name)) return std::nullopt;
    return r.name;
}

// One row per distinct type. NO .row_count() shortcut: DIA's get_Count(SymTagUDT)
// is *slower* than enumerating on a large PDB -- measured on a 3.14 GB PDB, the
// shortcut blew past the 60 s default timeout and errored, while a full walk plus
// dedup returned 1,229,669 rows in 59 s. It also could not answer the deduped
// count anyway.
inline GeneratorTableDef<CachedSymbol> define_udts_table(PdbSession& session) {
    return generator_table<CachedSymbol>("udts")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<DedupedSymbolGenerator>(session, SymTagUDT, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column("name", xsql::ColumnType::Text,
                xsql::detail::row_getter_nullable_text<CachedSymbol>(type_name_or_null))
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

// The raw per-compiland type records behind `udts`. Use this for "how many
// translation units define this type" and other per-record questions.
inline GeneratorTableDef<CachedSymbol> define_udt_records_table(PdbSession& session) {
    return generator_table<CachedSymbol>("udt_records")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<SymbolGenerator>(session, SymTagUDT, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column("name", xsql::ColumnType::Text,
                xsql::detail::row_getter_nullable_text<CachedSymbol>(type_name_or_null))
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

// Enums table -- same dedup model as udts.
inline GeneratorTableDef<CachedSymbol> define_enums_table(PdbSession& session) {
    return generator_table<CachedSymbol>("enums")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<DedupedSymbolGenerator>(session, SymTagEnum, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column("name", xsql::ColumnType::Text,
                xsql::detail::row_getter_nullable_text<CachedSymbol>(type_name_or_null))
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

inline GeneratorTableDef<CachedSymbol> define_enum_records_table(PdbSession& session) {
    return generator_table<CachedSymbol>("enum_records")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<SymbolGenerator>(session, SymTagEnum, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column("name", xsql::ColumnType::Text,
                xsql::detail::row_getter_nullable_text<CachedSymbol>(type_name_or_null))
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

// Typedefs table
inline GeneratorTableDef<CachedSymbol> define_typedefs_table(PdbSession& session) {
    return generator_table<CachedSymbol>("typedefs")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .row_count([&session]() { return to_size_t_clamped(session.count_symbols(SymTagTypedef)); })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<SymbolGenerator>(session, SymTagTypedef, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

// Compilands table
inline GeneratorTableDef<CachedCompiland> define_compilands_table(PdbSession& session) {
    return generator_table<CachedCompiland>("compilands")
        .estimate_rows([]() { return kSymbolRowEstimate; })
        .row_count([&session]() { return to_size_t_clamped(session.count_symbols(SymTagCompiland)); })
        .generator([&session]() { return std::make_unique<CompilandGenerator>(session); })
        .column_int64("id", [](const CachedCompiland& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedCompiland& r) { return r.name; })
        .column_text("library", [](const CachedCompiland& r) { return r.library_name; })
        // NULL rather than a misleading 0 when the compiland reports no language at
        // all (~10% of compilands on a real shipping PDB have no CompilandDetails
        // child). 0 is a valid CV_CFL_LANG value meaning C, so it cannot double as
        // "unknown".
        // TEXT, and NULL when the compiland records no language at all (~10% of
        // compilands on a real shipping PDB). An unrecognized code passes through
        // as its number so nothing is silently lost.
        .column("language", xsql::ColumnType::Text,
                xsql::detail::row_getter_nullable_text<CachedCompiland>(
                    [](const CachedCompiland& r) -> std::optional<std::string> {
                        if (!r.has_language) return std::nullopt;
                        const std::string t = language_text(r.language);
                        return t.empty() ? std::to_string(r.language) : t;
                    }))
        .build();
}

// Source files table
inline GeneratorTableDef<CachedSourceFile> define_source_files_table(PdbSession& session) {
    return generator_table<CachedSourceFile>("source_files")
        .estimate_rows([]() { return static_cast<size_t>(1000); })
        .generator([&session]() { return std::make_unique<SourceFileGenerator>(session); })
        .column_int64("id", [](const CachedSourceFile& r) { return static_cast<int64_t>(r.id); })
        .column_text("filename", [](const CachedSourceFile& r) { return r.filename; })
        .column_text("checksum_type", [](const CachedSourceFile& r) { return checksum_text(r.checksum_type); })
        .build();
}

// Line numbers table
inline GeneratorTableDef<CachedLineNumber> define_line_numbers_table(PdbSession& session) {
    return generator_table<CachedLineNumber>("line_numbers")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<LineNumberGenerator>(session); })
        .column_int64("file_id", [](const CachedLineNumber& r) { return static_cast<int64_t>(r.file_id); })
        .column_int("line", [](const CachedLineNumber& r) { return static_cast<int>(r.line); })
        .column_int("column", [](const CachedLineNumber& r) { return static_cast<int>(r.column); })
        .column_int64("rva", [](const CachedLineNumber& r) { return static_cast<int64_t>(r.rva); })
        .column_int("length", [](const CachedLineNumber& r) { return static_cast<int>(r.length); })
        .column_int64("compiland_id", [](const CachedLineNumber& r) { return static_cast<int64_t>(r.compiland_id); })
        .build();
}

// Sections table
inline GeneratorTableDef<CachedSection> define_sections_table(PdbSession& session) {
    return generator_table<CachedSection>("sections")
        // PE images have a handful of sections; a small constant is plenty for
        // the planner (the generator streams the SECTIONHEADERS records directly).
        .estimate_rows([]() { return static_cast<size_t>(16); })
        .generator([&session]() { return std::make_unique<SectionGenerator>(session); })
        .column_int("number", [](const CachedSection& r) { return static_cast<int>(r.section_number); })
        .column_text("name", [](const CachedSection& r) { return r.name; })
        .column_int64("rva", [](const CachedSection& r) { return static_cast<int64_t>(r.rva); })
        .column_int("length", [](const CachedSection& r) { return static_cast<int>(r.length); })
        // characteristics is a DWORD; IMAGE_SCN_MEM_WRITE (0x80000000) sets the high
        // bit, so a signed int would surface a negative value. Widen to int64 and mask
        // to 32 bits (matches idasql/ghidra 32-bit-flag exposure).
        .column_int64("characteristics", [](const CachedSection& r) { return static_cast<int64_t>(r.characteristics) & 0xFFFFFFFFLL; })
        .column_int("readable", [](const CachedSection& r) { return r.read ? 1 : 0; })
        .column_int("writable", [](const CachedSection& r) { return r.write ? 1 : 0; })
        .column_int("executable", [](const CachedSection& r) { return r.execute ? 1 : 0; })
        .column_int("code", [](const CachedSection& r) { return r.code ? 1 : 0; })
        .build();
}

// Thunks table
// Thunks are compiland children, so both the scan and the count must walk
// compilands. No .row_count() override: count_symbols() asks the global scope,
// which reports 0 and would contradict the scan.
inline GeneratorTableDef<CachedSymbol> define_thunks_table(PdbSession& session) {
    return generator_table<CachedSymbol>("thunks")
        .estimate_rows([]() { return static_cast<size_t>(10000); })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<NestedSymbolGenerator>(session, SymTagCompiland, SymTagThunk, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .build();
}

// Labels are function children -- same reasoning as thunks above.
inline GeneratorTableDef<CachedSymbol> define_labels_table(PdbSession& session) {
    return generator_table<CachedSymbol>("labels")
        .estimate_rows([]() { return static_cast<size_t>(10000); })
        .projection_generator([&session](uint64_t col_used) { return std::make_unique<NestedSymbolGenerator>(session, SymTagFunction, SymTagLabel, symbol_projection_from(col_used, -1)); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        .build();
}

// Data members of structs/classes/unions.
//
// Fields and methods are separate tables rather than one table with a `kind`
// discriminator, so every column is meaningful on every row: a field always has
// an offset; a method never does, and only a method can be virtual or pure.
inline GeneratorTableDef<CachedMember> define_udt_fields_table(PdbSession& session) {
    return generator_table<CachedMember>("udt_fields")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<MemberGenerator>(session, SymTagData); })
        .column_int64("udt_id", [](const CachedMember& r) { return static_cast<int64_t>(r.parent_id); })
        .column_text("udt_name", [](const CachedMember& r) { return r.parent_name; })
        .column_int64("id", [](const CachedMember& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedMember& r) { return r.name; })
        .column_text("type", [](const CachedMember& r) { return r.type_name; })
        .column_int("offset", [](const CachedMember& r) { return static_cast<int>(r.offset); })
        .column_int64("length", [](const CachedMember& r) { return static_cast<int64_t>(r.length); })
        .column_text("access", [](const CachedMember& r) { return access_text(r.access); })
        .column_int("is_static", [](const CachedMember& r) { return r.is_static ? 1 : 0; })
        .build();
}

// Member functions of structs/classes/unions. `type` is the rendered signature.
inline GeneratorTableDef<CachedMember> define_udt_methods_table(PdbSession& session) {
    return generator_table<CachedMember>("udt_methods")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<MemberGenerator>(session, SymTagFunction); })
        .column_int64("udt_id", [](const CachedMember& r) { return static_cast<int64_t>(r.parent_id); })
        .column_text("udt_name", [](const CachedMember& r) { return r.parent_name; })
        .column_int64("id", [](const CachedMember& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedMember& r) { return r.name; })
        .column_text("type", [](const CachedMember& r) { return r.type_name; })
        .column_int64("length", [](const CachedMember& r) { return static_cast<int64_t>(r.length); })
        .column_text("access", [](const CachedMember& r) { return access_text(r.access); })
        .column_int("is_static", [](const CachedMember& r) { return r.is_static ? 1 : 0; })
        .column_int("is_virtual", [](const CachedMember& r) { return r.is_virtual ? 1 : 0; })
        .column_int("is_pure", [](const CachedMember& r) { return r.is_pure ? 1 : 0; })
        .build();
}

// Enum values table
inline GeneratorTableDef<CachedEnumValue> define_enum_values_table(PdbSession& session) {
    return generator_table<CachedEnumValue>("enum_values")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<EnumValueGenerator>(session); })
        .column_int64("enum_id", [](const CachedEnumValue& r) { return static_cast<int64_t>(r.enum_id); })
        .column_text("enum_name", [](const CachedEnumValue& r) { return r.enum_name; })
        .column_int64("id", [](const CachedEnumValue& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedEnumValue& r) { return r.name; })
        .column_int64("value", [](const CachedEnumValue& r) { return r.value; })
        .build();
}

// Base classes table
inline GeneratorTableDef<CachedBaseClass> define_base_classes_table(PdbSession& session) {
    return generator_table<CachedBaseClass>("base_classes")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<BaseClassGenerator>(session); })
        .column_int64("derived_id", [](const CachedBaseClass& r) { return static_cast<int64_t>(r.derived_id); })
        .column_text("derived_name", [](const CachedBaseClass& r) { return r.derived_name; })
        .column_int64("base_id", [](const CachedBaseClass& r) { return static_cast<int64_t>(r.base_id); })
        .column_text("base_name", [](const CachedBaseClass& r) { return r.base_name; })
        .column_int("offset", [](const CachedBaseClass& r) { return static_cast<int>(r.offset); })
        .column_int("is_virtual", [](const CachedBaseClass& r) { return r.is_virtual ? 1 : 0; })
        .column_text("access", [](const CachedBaseClass& r) { return access_text(r.access); })
        .build();
}

// Locals table
inline GeneratorTableDef<CachedLocal> define_locals_table(PdbSession& session) {
    return generator_table<CachedLocal>("locals")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<LocalOrParamGenerator>(session, DataIsLocal); })
        .column_int64("func_id", [](const CachedLocal& r) { return static_cast<int64_t>(r.func_id); })
        .column_text("func_name", [](const CachedLocal& r) { return r.func_name; })
        .column_int64("id", [](const CachedLocal& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedLocal& r) { return r.name; })
        .column_text("type", [](const CachedLocal& r) { return r.type_name; })
        .column_text("location", [](const CachedLocal& r) { return location_text(r.location_type); })
        .column("frame_offset", xsql::ColumnType::Integer,
                xsql::detail::row_getter_nullable_int<CachedLocal>(
                    [](const CachedLocal& r) -> std::optional<int> {
                        if (!r.has_frame_offset) return std::nullopt;
                        return static_cast<int>(r.frame_offset);
                    }))
        .column("register", xsql::ColumnType::Integer,
                xsql::detail::row_getter_nullable_int<CachedLocal>(
                    [](const CachedLocal& r) -> std::optional<int> {
                        if (!r.has_register) return std::nullopt;
                        return static_cast<int>(r.register_id);
                    }))
        .build();
}

// Parameters table
inline GeneratorTableDef<CachedLocal> define_parameters_table(PdbSession& session) {
    return generator_table<CachedLocal>("parameters")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<LocalOrParamGenerator>(session, DataIsParam); })
        .column_int64("func_id", [](const CachedLocal& r) { return static_cast<int64_t>(r.func_id); })
        .column_text("func_name", [](const CachedLocal& r) { return r.func_name; })
        .column_int64("id", [](const CachedLocal& r) { return static_cast<int64_t>(r.id); })
        // 0-based position in the signature. Without this, parameter order was
        // only recoverable by relying on generator emission order, which SQL does
        // not guarantee -- so ORDER BY ordinal is the only correct way to
        // reconstruct a call signature.
        .column_int64("ordinal", [](const CachedLocal& r) { return r.ordinal; })
        .column_text("name", [](const CachedLocal& r) { return r.name; })
        .column_text("type", [](const CachedLocal& r) { return r.type_name; })
        .column_text("location", [](const CachedLocal& r) { return location_text(r.location_type); })
        .column("frame_offset", xsql::ColumnType::Integer,
                xsql::detail::row_getter_nullable_int<CachedLocal>(
                    [](const CachedLocal& r) -> std::optional<int> {
                        if (!r.has_frame_offset) return std::nullopt;
                        return static_cast<int>(r.frame_offset);
                    }))
        .column("register", xsql::ColumnType::Integer,
                xsql::detail::row_getter_nullable_int<CachedLocal>(
                    [](const CachedLocal& r) -> std::optional<int> {
                        if (!r.has_register) return std::nullopt;
                        return static_cast<int>(r.register_id);
                    }))
        .build();
}

// ============================================================================
// Table Registry
// ============================================================================

class TableRegistry {
    PdbSession& session_;

    GeneratorTableDef<CachedSymbol> functions_;
    GeneratorTableDef<CachedSymbol> publics_;
    GeneratorTableDef<CachedSymbol> data_;
    GeneratorTableDef<CachedSymbol> udts_;
    GeneratorTableDef<CachedSymbol> udt_records_;
    GeneratorTableDef<CachedSymbol> enums_;
    GeneratorTableDef<CachedSymbol> enum_records_;
    GeneratorTableDef<CachedSymbol> typedefs_;
    GeneratorTableDef<CachedSymbol> thunks_;
    GeneratorTableDef<CachedSymbol> labels_;
    GeneratorTableDef<CachedSymbol> symbol_at_;  // TVF: innermost symbol containing an addr

    GeneratorTableDef<CachedCompiland> compilands_;
    GeneratorTableDef<CachedSourceFile> source_files_;
    GeneratorTableDef<CachedLineNumber> line_numbers_;

    GeneratorTableDef<CachedSection> sections_;

    GeneratorTableDef<CachedMember> udt_fields_;
    GeneratorTableDef<CachedMember> udt_methods_;
    GeneratorTableDef<CachedEnumValue> enum_values_;
    GeneratorTableDef<CachedBaseClass> base_classes_;

    GeneratorTableDef<CachedLocal> locals_;
    GeneratorTableDef<CachedLocal> parameters_;

    // Shared runtime_settings table (query_timeout_ms, timeout_push/pop, ...),
    // bound to the pdbsql process-wide RuntimeSettingsCore singleton.
    xsql::CachedTableDef<xsql::runtime::RuntimeSettingEntry> runtime_settings_;

    template<typename RowData>
    static void register_one(xsql::Database& db, GeneratorTableDef<RowData>& def) {
        std::string module_name = "pdb_" + def.name;
        db.register_generator_table(module_name.c_str(), &def);
        db.create_table(def.name.c_str(), module_name.c_str());
    }

public:
    explicit TableRegistry(PdbSession& session)
        : session_(session)
        , functions_(define_functions_table(session_))
        , publics_(define_publics_table(session_))
        , data_(define_data_table(session_))
        , udts_(define_udts_table(session_))
        , udt_records_(define_udt_records_table(session_))
        , enums_(define_enums_table(session_))
        , enum_records_(define_enum_records_table(session_))
        , typedefs_(define_typedefs_table(session_))
        , thunks_(define_thunks_table(session_))
        , labels_(define_labels_table(session_))
        , symbol_at_(define_symbol_at_table(session_))
        , compilands_(define_compilands_table(session_))
        , source_files_(define_source_files_table(session_))
        , line_numbers_(define_line_numbers_table(session_))
        , sections_(define_sections_table(session_))
        , udt_fields_(define_udt_fields_table(session_))
        , udt_methods_(define_udt_methods_table(session_))
        , enum_values_(define_enum_values_table(session_))
        , base_classes_(define_base_classes_table(session_))
        , locals_(define_locals_table(session_))
        , parameters_(define_parameters_table(session_))
        , runtime_settings_(xsql::runtime::define_runtime_settings_table(
              pdbsql::runtime_settings(), "pdbsql"))
    {
        auto* functions_def = &functions_;
        add_filter_eq(functions_, "id",
                      [functions_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedSymbol>>(functions_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                              functions_def,
                              std::make_unique<SymbolByIdGenerator>(session_, static_cast<DWORD>(id), SymTagFunction));
                      },
                      1.0, 1.0);
        add_filter_eq_text(functions_, "name",
                           [functions_def, this](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                               return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                                   functions_def,
                                   std::make_unique<SymbolByNameGenerator>(session_, SymTagFunction, name ? name : ""));
                           },
                           5.0, 10.0);
        // WHERE rva = X: direct DIA address-index lookup (findSymbolByRVA), not a full
        // walk. Cache-free; cost=1 so the planner strongly prefers it over a scan.
        add_filter_eq(functions_, "rva",
                      [functions_def, this](int64_t rva) -> std::unique_ptr<xsql::RowIterator> {
                          if (rva < 0 || rva > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedSymbol>>(functions_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                              functions_def,
                              std::make_unique<SymbolByRvaGenerator>(session_, static_cast<DWORD>(rva), SymTagFunction));
                      },
                      1.0, 1.0);
        // Bounded WHERE rva > / >= / < / <= X (and BETWEEN, which SQLite expands to a
        // GE+LE pair): one symbolByRVA seek + a linear walk stopping at the upper
        // bound. A reconnect/resume aid and a genuine analytical range query -- NOT a
        // per-page pagination mechanism (see SymbolRangeGenerator's doc comment).
        add_constraint_range_filter<CachedSymbol>(
            functions_, "rva",
            [this](const std::vector<xsql::GeneratorConstraintArg>& args) {
                return make_symbol_range_generator(session_, SymTagFunction, args);
            },
            5.0, 1000.0);

        auto* publics_def = &publics_;
        add_filter_eq(publics_, "id",
                      [publics_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedSymbol>>(publics_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                              publics_def,
                              std::make_unique<SymbolByIdGenerator>(session_, static_cast<DWORD>(id), SymTagPublicSymbol));
                      },
                      1.0, 1.0);
        add_filter_eq_text(publics_, "name",
                           [publics_def, this](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                               return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                                   publics_def,
                                   std::make_unique<SymbolByNameGenerator>(session_, SymTagPublicSymbol, name ? name : ""));
                           },
                           5.0, 10.0);
        add_filter_eq(publics_, "rva",
                      [publics_def, this](int64_t rva) -> std::unique_ptr<xsql::RowIterator> {
                          if (rva < 0 || rva > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedSymbol>>(publics_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                              publics_def,
                              std::make_unique<SymbolByRvaGenerator>(session_, static_cast<DWORD>(rva), SymTagPublicSymbol));
                      },
                      1.0, 1.0);
        add_constraint_range_filter<CachedSymbol>(
            publics_, "rva",
            [this](const std::vector<xsql::GeneratorConstraintArg>& args) {
                return make_symbol_range_generator(session_, SymTagPublicSymbol, args);
            },
            5.0, 1000.0);

        auto* data_def = &data_;
        add_filter_eq(data_, "id",
                      [data_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedSymbol>>(data_def, nullptr);
                          }
                          auto accept = [](IDiaSymbol* symbol) -> bool {
                              if (!symbol) return false;
                              DWORD kind = 0;
                              if (FAILED(symbol->get_dataKind(&kind))) return false;
                              return kind == DataIsFileStatic || kind == DataIsGlobal || kind == DataIsConstant;
                          };
                          return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                              data_def,
                              std::make_unique<SymbolByIdGenerator>(session_, static_cast<DWORD>(id), SymTagData, accept));
                      },
                      1.0, 1.0);
        add_filter_eq_text(data_, "name",
                           [data_def, this](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                               return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                                   data_def,
                                   std::make_unique<SymbolByNameGenerator>(session_, SymTagData, name ? name : ""));
                           },
                           5.0, 10.0);

        // symbolById is scope-independent, so this is valid for globally-scoped and
        // nested symbol kinds alike.
        auto add_id_filter_only = [this](GeneratorTableDef<CachedSymbol>& def, enum SymTagEnum tag) {
            auto* def_ptr = &def;
            add_filter_eq(def, "id",
                          [def_ptr, this, tag](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                              if (id <= 0 || id > 0xFFFFFFFFLL) {
                                  return std::make_unique<GeneratorRowIterator<CachedSymbol>>(def_ptr, nullptr);
                              }
                              return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                                  def_ptr,
                                  std::make_unique<SymbolByIdGenerator>(session_, static_cast<DWORD>(id), tag));
                          },
                          1.0, 1.0);
        };

        auto add_name_and_id_filters = [this](GeneratorTableDef<CachedSymbol>& def, enum SymTagEnum tag) {
            auto* def_ptr = &def;
            add_filter_eq(def, "id",
                          [def_ptr, this, tag](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                              if (id <= 0 || id > 0xFFFFFFFFLL) {
                                  return std::make_unique<GeneratorRowIterator<CachedSymbol>>(def_ptr, nullptr);
                              }
                              return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                                  def_ptr,
                                  std::make_unique<SymbolByIdGenerator>(session_, static_cast<DWORD>(id), tag));
                          },
                          1.0, 1.0);
            add_filter_eq_text(def, "name",
                               [def_ptr, this, tag](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                                   return std::make_unique<GeneratorRowIterator<CachedSymbol>>(
                                       def_ptr,
                                       std::make_unique<SymbolByNameGenerator>(session_, tag, name ? name : ""));
                               },
                               5.0, 10.0);
        };

        // `udts`/`enums` are deduplicated, and DIA's name index resolves the one
        // canonical record -- which is exactly the deduplicated answer, so the
        // pushdown and a scan agree. The *_records tables keep the id filter only:
        // a name lookup there would return the single canonical record while a
        // scan returns every per-compiland record, i.e. a pushdown contradicting
        // its own table.
        add_name_and_id_filters(udts_, SymTagUDT);
        add_name_and_id_filters(enums_, SymTagEnum);
        add_id_filter_only(udt_records_, SymTagUDT);
        add_id_filter_only(enum_records_, SymTagEnum);
        add_name_and_id_filters(typedefs_, SymTagTypedef);
        // Thunks/labels get the id filter only. The by-name generator resolves
        // through the GLOBAL scope, which holds neither kind (they are compiland
        // and function children), so a name filter would return 0 rows while a
        // plain scan returns the symbol -- a pushdown that contradicts the table.
        // symbolById is scope-independent, so the id filter stays valid.
        add_id_filter_only(thunks_, SymTagThunk);
        add_id_filter_only(labels_, SymTagLabel);

        auto* compilands_def = &compilands_;
        add_filter_eq(compilands_, "id",
                      [compilands_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedCompiland>>(compilands_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedCompiland>>(
                              compilands_def,
                              std::make_unique<CompilandByIdGenerator>(session_, static_cast<DWORD>(id)));
                      },
                      1.0, 1.0);
        add_filter_eq_text(compilands_, "name",
                           [compilands_def, this](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                               return std::make_unique<GeneratorRowIterator<CachedCompiland>>(
                                   compilands_def,
                                   std::make_unique<CompilandByNameGenerator>(session_, name ? name : ""));
                           },
                           5.0, 10.0);

        auto* source_files_def = &source_files_;
        add_filter_eq(source_files_, "id",
                      [source_files_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedSourceFile>>(source_files_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedSourceFile>>(
                              source_files_def,
                              std::make_unique<SourceFileByIdGenerator>(session_, static_cast<DWORD>(id)));
                      },
                      1.0, 1.0);

        // udt_fields / udt_methods share the scoping filters; only the child tag
        // they enumerate differs.
        auto add_member_filters = [this](GeneratorTableDef<CachedMember>& def,
                                         enum SymTagEnum child_tag) {
            auto* def_ptr = &def;
            add_filter_eq(def, "udt_id",
                          [def_ptr, this, child_tag](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                              if (id <= 0 || id > 0xFFFFFFFFLL) {
                                  return std::make_unique<GeneratorRowIterator<CachedMember>>(def_ptr, nullptr);
                              }
                              return std::make_unique<GeneratorRowIterator<CachedMember>>(
                                  def_ptr,
                                  std::make_unique<UdtMembersByIdGenerator>(
                                      session_, static_cast<DWORD>(id), child_tag));
                          },
                          10.0, 100.0);
            add_filter_eq_text(def, "udt_name",
                               [def_ptr, this, child_tag](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                                   return std::make_unique<GeneratorRowIterator<CachedMember>>(
                                       def_ptr,
                                       std::make_unique<UdtMembersByNameGenerator>(
                                           session_, name ? name : "", child_tag));
                               },
                               10.0, 100.0);
        };
        add_member_filters(udt_fields_, SymTagData);
        add_member_filters(udt_methods_, SymTagFunction);

        auto* enum_values_def = &enum_values_;
        add_filter_eq(enum_values_, "enum_id",
                      [enum_values_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedEnumValue>>(enum_values_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedEnumValue>>(
                              enum_values_def,
                              std::make_unique<EnumValuesByIdGenerator>(session_, static_cast<DWORD>(id)));
                      },
                      10.0, 100.0);
        add_filter_eq_text(enum_values_, "enum_name",
                           [enum_values_def, this](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                               return std::make_unique<GeneratorRowIterator<CachedEnumValue>>(
                                   enum_values_def,
                                   std::make_unique<EnumValuesByNameGenerator>(session_, name ? name : ""));
                           },
                           10.0, 100.0);

        // base_classes pushdown covers the CHILD -> PARENT direction only, because
        // that is the only direction DIA indexes: findChildren(SymTagBaseClass)
        // answers "what does this class derive from", and there is no reverse
        // lookup for "what derives from this class". So `derived_id` and
        // `derived_name` are index-backed while `base_name`/`base_id` still scan --
        // seed a hierarchy walk from the derived side and traverse upward.
        auto* base_classes_def = &base_classes_;
        add_filter_eq(base_classes_, "derived_id",
                      [base_classes_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedBaseClass>>(base_classes_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedBaseClass>>(
                              base_classes_def,
                              std::make_unique<BaseClassesByDerivedIdGenerator>(session_, static_cast<DWORD>(id)));
                      },
                      10.0, 100.0);
        add_filter_eq_text(base_classes_, "derived_name",
                           [base_classes_def, this](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                               return std::make_unique<GeneratorRowIterator<CachedBaseClass>>(
                                   base_classes_def,
                                   std::make_unique<BaseClassesByDerivedNameGenerator>(session_, name ? name : ""));
                           },
                           10.0, 100.0);

        auto* locals_def = &locals_;
        add_filter_eq(locals_, "func_id",
                      [locals_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedLocal>>(locals_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedLocal>>(
                              locals_def,
                              std::make_unique<LocalOrParamByFuncIdGenerator>(session_, static_cast<DWORD>(id), DataIsLocal));
                      },
                      10.0, 100.0);

        auto* params_def = &parameters_;
        add_filter_eq(parameters_, "func_id",
                      [params_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedLocal>>(params_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedLocal>>(
                              params_def,
                              std::make_unique<LocalOrParamByFuncIdGenerator>(session_, static_cast<DWORD>(id), DataIsParam));
                      },
                      10.0, 100.0);

        auto* line_numbers_def = &line_numbers_;
        add_filter_eq(line_numbers_, "compiland_id",
                      [line_numbers_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedLineNumber>>(line_numbers_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedLineNumber>>(
                              line_numbers_def,
                              std::make_unique<LineNumbersByCompilandIdGenerator>(session_, static_cast<DWORD>(id)));
                      },
                      50.0, 1000.0);
    }

    void register_all(xsql::Database& db) {
        register_one(db, functions_);
        register_one(db, publics_);
        register_one(db, data_);
        register_one(db, udts_);
        register_one(db, udt_records_);
        register_one(db, enums_);
        register_one(db, enum_records_);
        register_one(db, typedefs_);
        register_one(db, thunks_);
        register_one(db, labels_);
        register_one(db, symbol_at_);

        register_one(db, compilands_);
        register_one(db, source_files_);
        register_one(db, line_numbers_);

        register_one(db, sections_);

        register_one(db, udt_fields_);
        register_one(db, udt_methods_);
        register_one(db, enum_values_);
        register_one(db, base_classes_);

        register_one(db, locals_);
        register_one(db, parameters_);

        db.register_cached_table("runtime_settings", &runtime_settings_);
        db.create_table("runtime_settings", "runtime_settings");
    }
};

} // namespace pdbsql
