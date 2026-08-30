// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
// pdb_session.hpp - PDB file session management

#include "dia_helpers.hpp"
#include <memory>
#include <optional>
#include <set>
#include <string>

namespace pdbsql {

// ============================================================================
// PDB Session - manages DIA lifecycle for a PDB file
// ============================================================================

class PdbSession {
public:
    PdbSession() = default;
    ~PdbSession() { close(); }

    // Non-copyable
    PdbSession(const PdbSession&) = delete;
    PdbSession& operator=(const PdbSession&) = delete;

    // Move semantics
    PdbSession(PdbSession&& other) noexcept {
        source_ = std::move(other.source_);
        session_ = std::move(other.session_);
        global_ = std::move(other.global_);
        path_ = std::move(other.path_);
    }

    PdbSession& operator=(PdbSession&& other) noexcept {
        if (this != &other) {
            close();
            source_ = std::move(other.source_);
            session_ = std::move(other.session_);
            global_ = std::move(other.global_);
            path_ = std::move(other.path_);
        }
        return *this;
    }

    // Open a PDB file
    bool open(const std::string& pdb_path) {
        close();

        // Create DiaDataSource. Try normal COM activation first so a machine with a
        // registered msdia keeps using it, then fall back to loading the DLL
        // directly -- the SDK is frequently present while the COM class is not
        // registered (registering it needs admin).
        HRESULT hr = source_.CoCreateInstance(CLSID_DiaSource);
        if (FAILED(hr)) {
            std::wstring loaded_from;
            const HRESULT regfree_hr = create_dia_source_regfree(source_, &loaded_from);
            if (FAILED(regfree_hr)) {
                if (hr == REGDB_E_CLASSNOTREG) {
                    last_error_ =
                        "Failed to create DiaSource: the DIA COM class is not registered (" +
                        hresult_to_string(hr) +
                        ") and no usable msdia140.dll was found to load directly (" +
                        hresult_to_string(regfree_hr) +
                        "). Install the Visual Studio C++ tools, place msdia140.dll next to this "
                        "executable, or register it with: regsvr32 \"<VS>\\DIA SDK\\bin\\amd64\\msdia140.dll\"";
                } else {
                    last_error_ = "Failed to create DiaSource (" + hresult_to_string(hr) + ")";
                }
                return false;
            }
        }

        // Load PDB
        std::wstring wpath = string_to_wstring(pdb_path);
        hr = source_->loadDataFromPdb(wpath.c_str());
        if (FAILED(hr)) {
            last_error_ = "Failed to load PDB: " + pdb_path + " -- " +
                          describe_pdb_load_error(hr) + " (" + hresult_to_string(hr) + ")";
            return false;
        }

        // Open session
        hr = source_->openSession(&session_);
        if (FAILED(hr)) {
            last_error_ = "Failed to open session (" + hresult_to_string(hr) + ")";
            return false;
        }

        // Get global scope
        hr = session_->get_globalScope(&global_);
        if (FAILED(hr)) {
            last_error_ = "Failed to get global scope (" + hresult_to_string(hr) + ")";
            return false;
        }

        path_ = pdb_path;
        return true;
    }

    void close() {
        global_.Release();
        session_.Release();
        source_.Release();
        path_.clear();
    }

    bool is_open() const { return session_ != nullptr; }
    const std::string& path() const { return path_; }
    const std::string& last_error() const { return last_error_; }

    // Access DIA interfaces
    IDiaSession* session() const { return session_; }
    IDiaSymbol* global() const { return global_; }

    // Enumerate children of a symbol
    CComPtr<IDiaEnumSymbols> enum_children(IDiaSymbol* parent, enum SymTagEnum symtag) {
        CComPtr<IDiaEnumSymbols> result;
        if (parent) {
            parent->findChildren(symtag, nullptr, nsNone, &result);
        }
        return result;
    }

    // Enumerate all symbols of a given type
    CComPtr<IDiaEnumSymbols> enum_symbols(enum SymTagEnum symtag) {
        return enum_children(global_, symtag);
    }

    // Find symbols by name
    CComPtr<IDiaEnumSymbols> find_symbols(const std::string& name, enum SymTagEnum symtag = SymTagNull) {
        CComPtr<IDiaEnumSymbols> result;
        if (global_) {
            std::wstring wname = string_to_wstring(name);
            global_->findChildren(symtag, wname.c_str(), nsCaseSensitive, &result);
        }
        return result;
    }

    // Find symbols by a DIA glob pattern (`*` = any run of chars, `?` = one
    // char -- DIA's nsfRegularExpression is glob syntax, not real regex,
    // despite the name). Used for `WHERE name LIKE ...` pushdown: DIA's own
    // glob search over a name index is dramatically cheaper than a full
    // client-side walk-and-compare on a large PDB (several times faster,
    // same match count). Case-insensitive to match SQL LIKE's default
    // semantics; the caller does not need an exact-superset guarantee here --
    // libxsql's LIKE pushdown always leaves the constraint unconsumed
    // (omit=0), so SQLite re-applies the real pattern to every returned row.
    CComPtr<IDiaEnumSymbols> find_symbols_glob(const std::string& glob_pattern,
                                                enum SymTagEnum symtag = SymTagNull) {
        CComPtr<IDiaEnumSymbols> result;
        if (global_) {
            std::wstring wpattern = string_to_wstring(glob_pattern);
            global_->findChildren(symtag, wpattern.c_str(), nsCaseInRegularExpression, &result);
        }
        return result;
    }

    // Same glob search, but over source file names (IDiaSession::findFile takes
    // the identical name/compareFlags shape as IDiaSymbol::findChildren, so this
    // mirrors find_symbols_glob() exactly). Used for `WHERE filename LIKE ...`
    // pushdown on source_files. A null pCompiland searches across the whole PDB,
    // same scope as SourceFileGenerator's unscoped walk.
    CComPtr<IDiaEnumSourceFiles> find_files_glob(const std::string& glob_pattern) {
        CComPtr<IDiaEnumSourceFiles> result;
        if (session_) {
            std::wstring wpattern = string_to_wstring(glob_pattern);
            session_->findFile(nullptr, wpattern.c_str(), nsCaseInRegularExpression, &result);
        }
        return result;
    }

    // Find the symbol at an RVA via DIA's native address index (findSymbolByRVA).
    // Cache-free: DIA owns the index, so this is a direct lookup, not a full walk.
    // findSymbolByRVA is containment-based (returns the symbol whose range contains
    // rva, which may start earlier), so a caller needing exact-start `WHERE rva = X`
    // semantics must confirm the returned symbol's RVA.
    CComPtr<IDiaSymbol> find_symbol_by_rva(DWORD rva, enum SymTagEnum symtag = SymTagNull) {
        CComPtr<IDiaSymbol> result;
        if (session_) {
            session_->findSymbolByRVA(rva, symtag, &result);
        }
        return result;
    }

    // Address-ordered symbol enumerator (all symbol kinds, by RVA). Used for a
    // BOUNDED range predicate (`WHERE rva BETWEEN a AND b`): the caller seeks with
    // symbolByRVA(start) -- which returns the symbol AT-OR-AFTER start directly, not
    // just positioning the cursor -- then walks forward with Next() until past the
    // upper bound. The seek itself is not O(1)/indexed, so this is meant for a single
    // bounded query or an occasional reconnect, not repeated per-page seeking.
    CComPtr<IDiaEnumSymbolsByAddr> symbols_by_addr() {
        CComPtr<IDiaEnumSymbolsByAddr> by_addr;
        if (session_) session_->getSymbolsByAddr(&by_addr);
        return by_addr;
    }

    // Get symbol count for a type. Delegates straight to DIA's enumerator count
    // (get_Count) — fast, and DIA already caches internally. pdbsql keeps NO
    // symbol-count cache of its own: libxsql's rule is no persistent caches (a
    // per-query scope at most), and a session-lifetime cache here would just
    // duplicate DIA. This is the exact count SELECT COUNT(*) resolves via the
    // COUNT_ONLY_SCAN fast path, and it never materializes rows.
    LONG count_symbols(enum SymTagEnum symtag) {
        auto symbols = enum_symbols(symtag);
        if (!symbols) return 0;
        LONG count = 0;
        symbols->get_Count(&count);
        return count;
    }

    // Resolve a source file by DIA's own uniqueId (the exact value pdbsql
    // exposes as `source_files.id` / `line_numbers.file_id`, see
    // extract_source_file()). findFileById(id) fails with E_INVALIDARG until
    // DIA's internal file-id index has been populated by at least one prior
    // findFile(compiland, ...) call PER COMPILAND in this session -- a
    // single unscoped findFile(nullptr, ...) (what SourceFileGenerator does)
    // is not enough. The warm-up walk costs seconds once; findFileById is
    // then ~free for the life of the session, and get_compilands() +
    // findLines(compiland, file) resolve one file's line records without
    // visiting any other compiland. This is what makes `WHERE file_id = X`
    // pushdown on `line_numbers` viable at all -- without it, findFileById on
    // a cold session cannot be used, leaving only the full
    // walk-every-compiland generator.
    bool ensure_file_index_warm() {
        if (file_index_warmed_) return true;
        if (!session_ || !global_) return false;

        CComPtr<IDiaEnumSymbols> compilands;
        if (FAILED(global_->findChildren(SymTagCompiland, nullptr, nsNone, &compilands)) || !compilands) {
            return false;
        }
        // Getting the per-compiland IDiaEnumSourceFiles enumerator and even
        // draining it via Next() is NOT enough to populate DIA's file-id
        // index -- empirically, findFileById still fails afterward. Only
        // calling get_uniqueId() on each returned IDiaSourceFile (as
        // SourceFileGenerator/extract_source_file() already do for every row
        // of a `source_files` scan) actually interns the id, which is what
        // lets findFileById resolve it later. See
        // Observed directly against DIA.
        for (;;) {
            CComPtr<IDiaSymbol> compiland;
            ULONG fetched = 0;
            if (FAILED(compilands->Next(1, &compiland, &fetched)) || fetched != 1) break;
            CComPtr<IDiaEnumSourceFiles> files;
            if (SUCCEEDED(session_->findFile(compiland, nullptr, nsNone, &files)) && files) {
                for (;;) {
                    CComPtr<IDiaSourceFile> file;
                    ULONG ffetched = 0;
                    if (FAILED(files->Next(1, &file, &ffetched)) || ffetched != 1) break;
                    DWORD id = 0;
                    file->get_uniqueId(&id);
                }
            }
        }
        file_index_warmed_ = true;
        return true;
    }

    // Resolve a source file by id. Pays the one-time warm-up (see
    // ensure_file_index_warm()) on first use, then is effectively O(1).
    CComPtr<IDiaSourceFile> find_file_by_id(DWORD file_id) {
        CComPtr<IDiaSourceFile> result;
        if (!ensure_file_index_warm() || !session_) return result;
        session_->findFileById(file_id, &result);
        return result;
    }

    // Pays DIA's one-time SymTag enumeration warm-up for `tag` by walking the
    // whole table once. This is a pure-DIA cost, general across tags: the
    // first findChildren(tag)/Next() walk in a session pays a large fixed
    // cost plus a decaying per-row ramp before it reaches the warm rate, so a
    // small cold query can be orders of magnitude slower than the same query
    // warm. Calls get_name() per row (not just Next()) to match
    // extract_symbol()'s real per-row cost, so this warms what a real
    // scan/LIKE-pushdown/rva-pushdown needs, not just a bare enumeration.
    //
    // Idempotent per tag (checked against warmed_symtags_), so callers never
    // need to track it themselves.
    //
    // WARNING: tags vary enormously in per-symbol realization cost -- UDT/Enum
    // symbols are far more expensive than Function symbols, so fully warming
    // udts/enums on a huge PDB can itself take tens of seconds. That is why
    // warming is an explicit per-table opt-in (--warm-tables <list>) resolved
    // by the CLI, never applied to every table by default.
    bool ensure_symtag_warm(enum SymTagEnum tag) {
        if (warmed_symtags_.count(tag)) return true;
        if (!global_) return false;

        CComPtr<IDiaEnumSymbols> symbols;
        if (FAILED(global_->findChildren(tag, nullptr, nsNone, &symbols)) || !symbols) {
            return false;
        }
        for (;;) {
            CComPtr<IDiaSymbol> symbol;
            ULONG fetched = 0;
            if (FAILED(symbols->Next(1, &symbol, &fetched)) || fetched != 1) break;
            SafeBSTR name;
            symbol->get_name(name.ptr());
        }
        warmed_symtags_.insert(tag);
        return true;
    }

private:
    ComInit com_;  // Must be first - initializes COM
    CComPtr<IDiaDataSource> source_;
    CComPtr<IDiaSession> session_;
    CComPtr<IDiaSymbol> global_;
    std::string path_;
    std::string last_error_;
    bool file_index_warmed_ = false;
    std::set<enum SymTagEnum> warmed_symtags_;
};

// Maps a `--warm-tables` CLI table name to the SymTagEnum `ensure_symtag_warm()`
// needs. Deliberately covers only the tables whose real query path is a plain
// global-scope findChildren(tag) walk -- the exact shape ensure_symtag_warm()
// warms. Excludes: `line_numbers`/`source_files` (their own warm-up is
// findFileById-based, see ensure_file_index_warm()/--warm-file-index, an
// unrelated mechanism), `thunks`/`labels` (compiland-scoped children, not a
// single global-scope enumeration -- warming them would need a different
// walk), `udt_records`/`enum_records`/`udt_fields`/`udt_methods`/`enum_values`/
// `base_classes`/`locals`/`parameters`/`sections`/`symbol_at`/
// `runtime_settings` (not simple SymTag scans of the global scope at all).
inline std::optional<enum SymTagEnum> symtag_for_warmable_table_name(const std::string& name) {
    if (name == "functions") return SymTagFunction;
    if (name == "publics") return SymTagPublicSymbol;
    if (name == "data") return SymTagData;
    if (name == "udts") return SymTagUDT;
    if (name == "typedefs") return SymTagTypedef;
    if (name == "enums") return SymTagEnum;
    if (name == "compilands") return SymTagCompiland;
    return std::nullopt;
}

// ============================================================================
// Symbol info extraction helpers
// ============================================================================

struct SymbolInfo {
    DWORD id = 0;
    std::string name;
    std::string undecorated;
    DWORD rva = 0;
    ULONGLONG length = 0;
    enum SymTagEnum symtag = SymTagNull;
};

inline SymbolInfo extract_symbol_info(IDiaSymbol* symbol) {
    SymbolInfo info;
    if (!symbol) return info;

    symbol->get_symIndexId(&info.id);

    SafeBSTR name;
    if (SUCCEEDED(symbol->get_name(name.ptr()))) {
        info.name = name.str();
    }

    SafeBSTR undec;
    if (SUCCEEDED(symbol->get_undecoratedName(undec.ptr()))) {
        info.undecorated = undec.str();
    }

    symbol->get_relativeVirtualAddress(&info.rva);
    symbol->get_length(&info.length);

    DWORD tag = 0;
    symbol->get_symTag(&tag);
    info.symtag = static_cast<enum SymTagEnum>(tag);

    return info;
}

} // namespace pdbsql
