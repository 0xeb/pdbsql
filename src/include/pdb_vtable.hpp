#pragma once
/**
 * pdb_vtable.hpp - SQLite Virtual Table framework for PDB files
 *
 * Ported from idasql with adaptations for MSDIA.
 *
 * Features:
 *   - Declarative column definitions using lambdas
 *   - Lazy iteration (index-based, no pre-collection)
 *   - Type-safe column accessors
 *   - Fluent builder API
 *
 * Example usage:
 *
 *   auto symbols_def = pdbsql::table("symbols")
 *       .count([&]() { return get_symbol_count(session); })
 *       .column_int64("id", [&](size_t i) { return get_symbol_id(session, i); })
 *       .column_text("name", [&](size_t i) { return get_symbol_name(session, i); })
 *       .build();
 *
 *   pdbsql::register_vtable(db, "pdb_symbols", &symbols_def);
 *   pdbsql::create_vtable(db, "symbols", "pdb_symbols");
 */

#include <sqlite3.h>
#include <string>
#include <vector>
#include <functional>
#include <cstring>
#include <sstream>

namespace pdbsql {

// ============================================================================
// Column Types
// ============================================================================

enum class ColumnType {
    Integer,
    Text,
    Real,
    Blob
};

inline const char* column_type_sql(ColumnType t) {
    switch (t) {
        case ColumnType::Integer: return "INTEGER";
        case ColumnType::Text:    return "TEXT";
        case ColumnType::Real:    return "REAL";
        case ColumnType::Blob:    return "BLOB";
    }
    return "TEXT";
}

// ============================================================================
// Column Definition
// ============================================================================

struct ColumnDef {
    std::string name;
    ColumnType type;
    std::function<void(sqlite3_context*, size_t)> bind;

    ColumnDef(const char* n, ColumnType t,
              std::function<void(sqlite3_context*, size_t)> b)
        : name(n), type(t), bind(std::move(b)) {}
};

// Column factory helpers
inline ColumnDef make_column_int64(const char* name,
                                    std::function<int64_t(size_t)> getter) {
    return ColumnDef(name, ColumnType::Integer,
        [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
            sqlite3_result_int64(ctx, getter(idx));
        });
}

inline ColumnDef make_column_int(const char* name,
                                  std::function<int(size_t)> getter) {
    return ColumnDef(name, ColumnType::Integer,
        [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
            sqlite3_result_int(ctx, getter(idx));
        });
}

inline ColumnDef make_column_text(const char* name,
                                   std::function<std::string(size_t)> getter) {
    return ColumnDef(name, ColumnType::Text,
        [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
            std::string val = getter(idx);
            sqlite3_result_text(ctx, val.c_str(), -1, SQLITE_TRANSIENT);
        });
}

inline ColumnDef make_column_double(const char* name,
                                     std::function<double(size_t)> getter) {
    return ColumnDef(name, ColumnType::Real,
        [getter = std::move(getter)](sqlite3_context* ctx, size_t idx) {
            sqlite3_result_double(ctx, getter(idx));
        });
}

// ============================================================================
// Virtual Table Definition
// ============================================================================

struct VTableDef {
    std::string name;
    std::function<size_t()> row_count;
    std::vector<ColumnDef> columns;

    std::string schema() const {
        std::ostringstream ss;
        ss << "CREATE TABLE " << name << "(";
        for (size_t i = 0; i < columns.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << columns[i].name << " " << column_type_sql(columns[i].type);
        }
        ss << ")";
        return ss.str();
    }
};

// ============================================================================
// SQLite Virtual Table Implementation
// ============================================================================

struct GenericVtab {
    sqlite3_vtab base;
    const VTableDef* def;
};

struct GenericCursor {
    sqlite3_vtab_cursor base;
    size_t idx;
    size_t total;
    const VTableDef* def;
};

// xConnect/xCreate
inline int vtab_connect(sqlite3* db, void* pAux, int, const char* const*,
                        sqlite3_vtab** ppVtab, char**) {
    const VTableDef* def = static_cast<const VTableDef*>(pAux);

    int rc = sqlite3_declare_vtab(db, def->schema().c_str());
    if (rc != SQLITE_OK) return rc;

    auto* vtab = new GenericVtab();
    memset(&vtab->base, 0, sizeof(vtab->base));
    vtab->def = def;
    *ppVtab = &vtab->base;
    return SQLITE_OK;
}

// xDisconnect/xDestroy
inline int vtab_disconnect(sqlite3_vtab* pVtab) {
    delete reinterpret_cast<GenericVtab*>(pVtab);
    return SQLITE_OK;
}

// xOpen
inline int vtab_open(sqlite3_vtab* pVtab, sqlite3_vtab_cursor** ppCursor) {
    auto* vtab = reinterpret_cast<GenericVtab*>(pVtab);
    auto* cursor = new GenericCursor();
    memset(&cursor->base, 0, sizeof(cursor->base));
    cursor->idx = 0;
    cursor->total = vtab->def->row_count();
    cursor->def = vtab->def;
    *ppCursor = &cursor->base;
    return SQLITE_OK;
}

// xClose
inline int vtab_close(sqlite3_vtab_cursor* pCursor) {
    delete reinterpret_cast<GenericCursor*>(pCursor);
    return SQLITE_OK;
}

// xNext
inline int vtab_next(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<GenericCursor*>(pCursor);
    cursor->idx++;
    return SQLITE_OK;
}

// xEof
inline int vtab_eof(sqlite3_vtab_cursor* pCursor) {
    auto* cursor = reinterpret_cast<GenericCursor*>(pCursor);
    return cursor->idx >= cursor->total;
}

// xColumn
inline int vtab_column(sqlite3_vtab_cursor* pCursor, sqlite3_context* ctx, int col) {
    auto* cursor = reinterpret_cast<GenericCursor*>(pCursor);
    if (col < 0 || static_cast<size_t>(col) >= cursor->def->columns.size()) {
        sqlite3_result_null(ctx);
        return SQLITE_OK;
    }
    cursor->def->columns[col].bind(ctx, cursor->idx);
    return SQLITE_OK;
}

// xRowid
inline int vtab_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    auto* cursor = reinterpret_cast<GenericCursor*>(pCursor);
    *pRowid = static_cast<sqlite3_int64>(cursor->idx);
    return SQLITE_OK;
}

// xFilter
inline int vtab_filter(sqlite3_vtab_cursor* pCursor, int, const char*, int, sqlite3_value**) {
    auto* cursor = reinterpret_cast<GenericCursor*>(pCursor);
    cursor->idx = 0;
    cursor->total = cursor->def->row_count();
    return SQLITE_OK;
}

// xBestIndex
inline int vtab_best_index(sqlite3_vtab* pVtab, sqlite3_index_info* pInfo) {
    auto* vtab = reinterpret_cast<GenericVtab*>(pVtab);
    size_t count = vtab->def->row_count();
    pInfo->estimatedCost = static_cast<double>(count);
    pInfo->estimatedRows = count;
    return SQLITE_OK;
}

// Create module definition
inline sqlite3_module create_module() {
    sqlite3_module mod = {};
    mod.iVersion = 0;
    mod.xCreate = vtab_connect;
    mod.xConnect = vtab_connect;
    mod.xBestIndex = vtab_best_index;
    mod.xDisconnect = vtab_disconnect;
    mod.xDestroy = vtab_disconnect;
    mod.xOpen = vtab_open;
    mod.xClose = vtab_close;
    mod.xFilter = vtab_filter;
    mod.xNext = vtab_next;
    mod.xEof = vtab_eof;
    mod.xColumn = vtab_column;
    mod.xRowid = vtab_rowid;
    return mod;
}

// Global module instance
inline sqlite3_module& get_module() {
    static sqlite3_module mod = create_module();
    return mod;
}

// ============================================================================
// Registration Helper
// ============================================================================

inline bool register_vtable(sqlite3* db, const char* module_name, const VTableDef* def) {
    int rc = sqlite3_create_module_v2(db, module_name, &get_module(),
                                       const_cast<VTableDef*>(def), nullptr);
    return rc == SQLITE_OK;
}

inline bool create_vtable(sqlite3* db, const char* table_name, const char* module_name) {
    std::string sql = "CREATE VIRTUAL TABLE " + std::string(table_name) +
                      " USING " + std::string(module_name) + ";";
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

// ============================================================================
// Table Builder (Fluent API)
// ============================================================================

class VTableBuilder {
    VTableDef def_;
public:
    explicit VTableBuilder(const char* name) {
        def_.name = name;
    }

    VTableBuilder& count(std::function<size_t()> fn) {
        def_.row_count = std::move(fn);
        return *this;
    }

    VTableBuilder& column_int64(const char* name, std::function<int64_t(size_t)> getter) {
        def_.columns.push_back(make_column_int64(name, std::move(getter)));
        return *this;
    }

    VTableBuilder& column_int(const char* name, std::function<int(size_t)> getter) {
        def_.columns.push_back(make_column_int(name, std::move(getter)));
        return *this;
    }

    VTableBuilder& column_text(const char* name, std::function<std::string(size_t)> getter) {
        def_.columns.push_back(make_column_text(name, std::move(getter)));
        return *this;
    }

    VTableBuilder& column_double(const char* name, std::function<double(size_t)> getter) {
        def_.columns.push_back(make_column_double(name, std::move(getter)));
        return *this;
    }

    VTableDef build() { return std::move(def_); }
};

inline VTableBuilder table(const char* name) {
    return VTableBuilder(name);
}

// ============================================================================
// Convenience Macros
// ============================================================================

#define COLUMN_INT64(name, getter) \
    pdbsql::make_column_int64(#name, getter)

#define COLUMN_INT(name, getter) \
    pdbsql::make_column_int(#name, getter)

#define COLUMN_TEXT(name, getter) \
    pdbsql::make_column_text(#name, getter)

#define COLUMN_DOUBLE(name, getter) \
    pdbsql::make_column_double(#name, getter)

} // namespace pdbsql
