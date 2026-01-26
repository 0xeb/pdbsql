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
 *   sections      - PE sections from section contributions
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
#include "pdb_session.hpp"
#include <algorithm>
#include <vector>
#include <memory>
#include <unordered_map>

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
    DWORD language = 0;  // CV_CFL_C, CV_CFL_CXX, etc.
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
    int64_t offset_or_register = 0;
};

// ============================================================================
// Streaming Generators (lazy full scans; LIMIT-friendly)
// ============================================================================

inline size_t to_size_t_clamped(LONG v) {
    if (v <= 0) return 0;
    return static_cast<size_t>(v);
}

inline std::string safe_symbol_name(IDiaSymbol* symbol) {
    if (!symbol) return "";
    SafeBSTR name;
    if (SUCCEEDED(symbol->get_name(name.ptr()))) {
        return name.str();
    }
    return "";
}

inline CachedSymbol extract_symbol(IDiaSymbol* symbol) {
    CachedSymbol cs;
    if (!symbol) return cs;

    symbol->get_symIndexId(&cs.id);

    SafeBSTR name;
    if (SUCCEEDED(symbol->get_name(name.ptr()))) {
        cs.name = name.str();
    }

    SafeBSTR undec;
    if (SUCCEEDED(symbol->get_undecoratedName(undec.ptr()))) {
        cs.undecorated = undec.str();
    }

    symbol->get_relativeVirtualAddress(&cs.rva);
    symbol->get_length(&cs.length);
    symbol->get_symTag(&cs.symtag);

    DWORD section = 0, offset = 0;
    symbol->get_addressSection(&section);
    symbol->get_addressOffset(&offset);
    cs.section = section;
    cs.offset = offset;

    return cs;
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

    DWORD lang = 0;
    symbol->get_language(&lang);
    cc.language = lang;

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
    CComPtr<IDiaEnumSymbols> symbols_;
    CachedSymbol current_;
    sqlite3_int64 rowid_ = -1;
    bool started_ = false;

public:
    SymbolGenerator(PdbSession& session, enum SymTagEnum tag) : session_(session), tag_(tag) {}

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

        current_ = extract_symbol(symbol);
        ++rowid_;
        return true;
    }

    const CachedSymbol& current() const override { return current_; }
    sqlite3_int64 rowid() const override { return rowid_; }
};

class CompilandGenerator : public xsql::Generator<CachedCompiland> {
    PdbSession& session_;
    CComPtr<IDiaEnumSymbols> compilands_;
    CachedCompiland current_;
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class SourceFileGenerator : public xsql::Generator<CachedSourceFile> {
    PdbSession& session_;
    CComPtr<IDiaEnumSourceFiles> source_files_;
    CachedSourceFile current_;
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
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
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class SectionGenerator : public xsql::Generator<CachedSection> {
    PdbSession& session_;
    std::vector<CachedSection> sections_;
    size_t idx_ = 0;
    sqlite3_int64 rowid_ = -1;
    bool started_ = false;

    void build() {
        sections_.clear();

        IDiaSession* dia_session = session_.session();
        if (!dia_session) return;

        CComPtr<IDiaEnumTables> tables;
        if (FAILED(dia_session->getEnumTables(&tables)) || !tables) return;

        // Find section contributions table
        CComPtr<IDiaEnumSectionContribs> contribs;
        CComPtr<IDiaTable> table;
        ULONG tfetched = 0;
        while (SUCCEEDED(tables->Next(1, &table, &tfetched)) && tfetched == 1) {
            SafeBSTR name;
            if (SUCCEEDED(table->get_name(name.ptr()))) {
                if (wcscmp(name.get(), L"SectionContribs") == 0) {
                    table->QueryInterface(IID_IDiaEnumSectionContribs, (void**)&contribs);
                    break;
                }
            }
            table.Release();
        }
        if (!contribs) return;

        std::unordered_map<DWORD, CachedSection> sections;

        CComPtr<IDiaSectionContrib> contrib;
        ULONG cfetched = 0;
        while (SUCCEEDED(contribs->Next(1, &contrib, &cfetched)) && cfetched == 1) {
            DWORD sec_num = 0;
            contrib->get_addressSection(&sec_num);

            DWORD rva = 0, len = 0;
            contrib->get_relativeVirtualAddress(&rva);
            contrib->get_length(&len);

            auto [it, inserted] = sections.emplace(sec_num, CachedSection{});
            CachedSection& cs = it->second;

            if (inserted) {
                cs.section_number = sec_num;
                cs.rva = rva;
                cs.length = len;

                BOOL val = FALSE;
                if (SUCCEEDED(contrib->get_read(&val))) cs.read = (val != FALSE);
                if (SUCCEEDED(contrib->get_write(&val))) cs.write = (val != FALSE);
                if (SUCCEEDED(contrib->get_execute(&val))) cs.execute = (val != FALSE);
                if (SUCCEEDED(contrib->get_code(&val))) cs.code = (val != FALSE);
            } else {
                DWORD end = rva + len;
                DWORD cur_end = cs.rva + cs.length;
                if (end > cur_end) {
                    cs.length = end - cs.rva;
                }
            }

            contrib.Release();
        }

        sections_.reserve(sections.size());
        for (const auto& [num, sec] : sections) {
            sections_.push_back(sec);
        }

        std::sort(sections_.begin(), sections_.end(), [](const CachedSection& a, const CachedSection& b) {
            return a.section_number < b.section_number;
        });
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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class MemberGenerator : public xsql::Generator<CachedMember> {
    PdbSession& session_;
    CComPtr<IDiaEnumSymbols> udts_;
    CComPtr<IDiaSymbol> current_udt_;
    DWORD current_udt_id_ = 0;
    std::string current_udt_name_;
    CComPtr<IDiaEnumSymbols> members_;

    CachedMember current_;
    sqlite3_int64 rowid_ = -1;
    bool started_ = false;

    bool advance_udt() {
        current_udt_.Release();
        current_udt_id_ = 0;
        current_udt_name_.clear();
        members_.Release();

        CComPtr<IDiaSymbol> udt;
        ULONG fetched = 0;
        while (SUCCEEDED(udts_->Next(1, &udt, &fetched)) && fetched == 1) {
            current_udt_ = udt;
            current_udt_->get_symIndexId(&current_udt_id_);
            current_udt_name_ = safe_symbol_name(current_udt_);

            if (SUCCEEDED(current_udt_->findChildren(SymTagData, nullptr, nsNone, &members_)) && members_) {
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
    explicit MemberGenerator(PdbSession& session) : session_(session) {}

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

            current_ = {};
            current_.parent_id = current_udt_id_;
            current_.parent_name = current_udt_name_;

            member->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(member);

            CComPtr<IDiaSymbol> type;
            if (SUCCEEDED(member->get_type(&type)) && type) {
                current_.type_name = safe_symbol_name(type);
                ULONGLONG len = 0;
                type->get_length(&len);
                current_.length = len;
            }

            LONG offset = 0;
            member->get_offset(&offset);
            current_.offset = static_cast<DWORD>(offset);

            DWORD access = 0;
            member->get_access(&access);
            current_.access = access;

            DWORD loc_type = 0;
            member->get_locationType(&loc_type);
            current_.is_static = (loc_type == LocIsStatic);

            BOOL virt = FALSE;
            member->get_virtual(&virt);
            current_.is_virtual = (virt != FALSE);

            ++rowid_;
            return true;
        }
    }

    const CachedMember& current() const override { return current_; }
    sqlite3_int64 rowid() const override { return rowid_; }
};

class EnumValueGenerator : public xsql::Generator<CachedEnumValue> {
    PdbSession& session_;
    CComPtr<IDiaEnumSymbols> enums_;
    CComPtr<IDiaSymbol> current_enum_;
    DWORD current_enum_id_ = 0;
    std::string current_enum_name_;
    CComPtr<IDiaEnumSymbols> values_;

    CachedEnumValue current_;
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class BaseClassGenerator : public xsql::Generator<CachedBaseClass> {
    PdbSession& session_;
    CComPtr<IDiaEnumSymbols> udts_;
    CComPtr<IDiaSymbol> current_udt_;
    DWORD current_udt_id_ = 0;
    std::string current_udt_name_;
    CComPtr<IDiaEnumSymbols> bases_;

    CachedBaseClass current_;
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
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
    sqlite3_int64 rowid_ = -1;
    bool started_ = false;

    bool advance_func() {
        current_func_.Release();
        current_func_id_ = 0;
        current_func_name_.clear();
        data_syms_.Release();

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

            data->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(data);

            CComPtr<IDiaSymbol> type;
            if (SUCCEEDED(data->get_type(&type)) && type) {
                current_.type_name = safe_symbol_name(type);
            }

            DWORD loc_type = 0;
            data->get_locationType(&loc_type);
            current_.location_type = loc_type;

            LONG offset = 0;
            DWORD reg = 0;
            data->get_offset(&offset);
            data->get_registerId(&reg);
            current_.offset_or_register = (loc_type == LocIsRegRel) ? offset : static_cast<int64_t>(reg);

            ++rowid_;
            return true;
        }
    }

    const CachedLocal& current() const override { return current_; }
    sqlite3_int64 rowid() const override { return rowid_; }
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

    void column(sqlite3_context* ctx, int col) override {
        if (!ctx || eof_ || !def_) {
            sqlite3_result_null(ctx);
            return;
        }

        if (col < 0 || static_cast<size_t>(col) >= def_->columns.size()) {
            sqlite3_result_null(ctx);
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
        [factory = std::move(factory)](sqlite3_value* val) -> std::unique_ptr<xsql::RowIterator> {
            return factory(sqlite3_value_int64(val));
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
        [factory = std::move(factory)](sqlite3_value* val) -> std::unique_ptr<xsql::RowIterator> {
            const char* text = reinterpret_cast<const char*>(sqlite3_value_text(val));
            return factory(text ? text : "");
        });
}

// Filtered generators used by constraint pushdown (xBestIndex/xFilter).

class SymbolByNameGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    enum SymTagEnum tag_;
    std::string name_;
    CComPtr<IDiaEnumSymbols> symbols_;
    CachedSymbol current_;
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class SymbolByIdGenerator : public xsql::Generator<CachedSymbol> {
    PdbSession& session_;
    DWORD id_ = 0;
    enum SymTagEnum tag_;
    std::function<bool(IDiaSymbol*)> accept_;
    CachedSymbol current_;
    bool emitted_ = false;
    sqlite3_int64 rowid_ = -1;

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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class CompilandByNameGenerator : public xsql::Generator<CachedCompiland> {
    PdbSession& session_;
    std::string name_;
    CComPtr<IDiaEnumSymbols> compilands_;
    CachedCompiland current_;
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class CompilandByIdGenerator : public xsql::Generator<CachedCompiland> {
    PdbSession& session_;
    DWORD id_ = 0;
    CachedCompiland current_;
    bool emitted_ = false;
    sqlite3_int64 rowid_ = -1;

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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class SourceFileByIdGenerator : public xsql::Generator<CachedSourceFile> {
    PdbSession& session_;
    DWORD file_id_ = 0;
    CachedSourceFile current_;
    bool emitted_ = false;
    sqlite3_int64 rowid_ = -1;

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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class UdtMembersByIdGenerator : public xsql::Generator<CachedMember> {
    PdbSession& session_;
    DWORD udt_id_ = 0;
    bool started_ = false;
    DWORD parent_id_ = 0;
    std::string parent_name_;
    CComPtr<IDiaEnumSymbols> members_;
    CachedMember current_;
    sqlite3_int64 rowid_ = -1;

public:
    UdtMembersByIdGenerator(PdbSession& session, DWORD udt_id)
        : session_(session)
        , udt_id_(udt_id)
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
            if (FAILED(udt->findChildren(SymTagData, nullptr, nsNone, &members_)) || !members_) return false;
        }

        while (true) {
            CComPtr<IDiaSymbol> member;
            ULONG fetched = 0;
            if (FAILED(members_->Next(1, &member, &fetched)) || fetched != 1) {
                return false;
            }

            current_ = {};
            current_.parent_id = parent_id_;
            current_.parent_name = parent_name_;

            member->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(member);

            CComPtr<IDiaSymbol> type;
            if (SUCCEEDED(member->get_type(&type)) && type) {
                current_.type_name = safe_symbol_name(type);
                ULONGLONG len = 0;
                type->get_length(&len);
                current_.length = len;
            }

            LONG offset = 0;
            member->get_offset(&offset);
            current_.offset = static_cast<DWORD>(offset);

            DWORD access = 0;
            member->get_access(&access);
            current_.access = access;

            DWORD loc_type = 0;
            member->get_locationType(&loc_type);
            current_.is_static = (loc_type == LocIsStatic);

            BOOL virt = FALSE;
            member->get_virtual(&virt);
            current_.is_virtual = (virt != FALSE);

            ++rowid_;
            return true;
        }
    }

    const CachedMember& current() const override { return current_; }
    sqlite3_int64 rowid() const override { return rowid_; }
};

class UdtMembersByNameGenerator : public xsql::Generator<CachedMember> {
    PdbSession& session_;
    std::string udt_name_;

    CComPtr<IDiaEnumSymbols> udts_;
    CComPtr<IDiaSymbol> current_udt_;
    DWORD parent_id_ = 0;
    std::string parent_name_;
    CComPtr<IDiaEnumSymbols> members_;

    CachedMember current_;
    sqlite3_int64 rowid_ = -1;
    bool started_ = false;

    bool advance_udt() {
        current_udt_.Release();
        parent_id_ = 0;
        parent_name_.clear();
        members_.Release();

        CComPtr<IDiaSymbol> udt;
        ULONG fetched = 0;
        while (SUCCEEDED(udts_->Next(1, &udt, &fetched)) && fetched == 1) {
            current_udt_ = udt;
            current_udt_->get_symIndexId(&parent_id_);
            parent_name_ = safe_symbol_name(current_udt_);
            if (SUCCEEDED(current_udt_->findChildren(SymTagData, nullptr, nsNone, &members_)) && members_) {
                return true;
            }
            udt.Release();
            current_udt_.Release();
            parent_id_ = 0;
            parent_name_.clear();
        }
        return false;
    }

public:
    UdtMembersByNameGenerator(PdbSession& session, std::string udt_name)
        : session_(session)
        , udt_name_(std::move(udt_name))
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

            current_ = {};
            current_.parent_id = parent_id_;
            current_.parent_name = parent_name_;

            member->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(member);

            CComPtr<IDiaSymbol> type;
            if (SUCCEEDED(member->get_type(&type)) && type) {
                current_.type_name = safe_symbol_name(type);
                ULONGLONG len = 0;
                type->get_length(&len);
                current_.length = len;
            }

            LONG offset = 0;
            member->get_offset(&offset);
            current_.offset = static_cast<DWORD>(offset);

            DWORD access = 0;
            member->get_access(&access);
            current_.access = access;

            DWORD loc_type = 0;
            member->get_locationType(&loc_type);
            current_.is_static = (loc_type == LocIsStatic);

            BOOL virt = FALSE;
            member->get_virtual(&virt);
            current_.is_virtual = (virt != FALSE);

            ++rowid_;
            return true;
        }
    }

    const CachedMember& current() const override { return current_; }
    sqlite3_int64 rowid() const override { return rowid_; }
};

class EnumValuesByIdGenerator : public xsql::Generator<CachedEnumValue> {
    PdbSession& session_;
    DWORD enum_id_ = 0;
    bool started_ = false;
    std::string enum_name_;
    CComPtr<IDiaEnumSymbols> values_;
    CachedEnumValue current_;
    sqlite3_int64 rowid_ = -1;

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
    sqlite3_int64 rowid() const override { return rowid_; }
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
    sqlite3_int64 rowid_ = -1;
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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class BaseClassesByDerivedIdGenerator : public xsql::Generator<CachedBaseClass> {
    PdbSession& session_;
    DWORD derived_id_ = 0;
    bool started_ = false;
    std::string derived_name_;
    CComPtr<IDiaEnumSymbols> bases_;
    CachedBaseClass current_;
    sqlite3_int64 rowid_ = -1;

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

            current_ = {};
            current_.derived_id = derived_id_;
            current_.derived_name = derived_name_;

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
    sqlite3_int64 rowid() const override { return rowid_; }
};

class LocalOrParamByFuncIdGenerator : public xsql::Generator<CachedLocal> {
    PdbSession& session_;
    DWORD func_id_ = 0;
    DWORD want_kind_ = 0;
    bool started_ = false;
    std::string func_name_;
    CComPtr<IDiaEnumSymbols> data_syms_;
    CachedLocal current_;
    sqlite3_int64 rowid_ = -1;

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
            data->get_symIndexId(&current_.id);
            current_.name = safe_symbol_name(data);

            CComPtr<IDiaSymbol> type;
            if (SUCCEEDED(data->get_type(&type)) && type) {
                current_.type_name = safe_symbol_name(type);
            }

            DWORD loc_type = 0;
            data->get_locationType(&loc_type);
            current_.location_type = loc_type;

            LONG offset = 0;
            DWORD reg = 0;
            data->get_offset(&offset);
            data->get_registerId(&reg);
            current_.offset_or_register = (loc_type == LocIsRegRel) ? offset : static_cast<int64_t>(reg);

            ++rowid_;
            return true;
        }
    }

    const CachedLocal& current() const override { return current_; }
    sqlite3_int64 rowid() const override { return rowid_; }
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
    sqlite3_int64 rowid_ = -1;

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
    sqlite3_int64 rowid() const override { return rowid_; }
};

// ============================================================================
// Table Definitions
// ============================================================================

// Functions table
inline GeneratorTableDef<CachedSymbol> define_functions_table(PdbSession& session) {
    return generator_table<CachedSymbol>("functions")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagFunction)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagFunction); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_text("undecorated", [](const CachedSymbol& r) { return r.undecorated; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        .build();
}

// Public symbols table
inline GeneratorTableDef<CachedSymbol> define_publics_table(PdbSession& session) {
    return generator_table<CachedSymbol>("publics")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagPublicSymbol)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagPublicSymbol); })
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
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagData)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagData); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        .build();
}

// UDT (structs/classes) table
inline GeneratorTableDef<CachedSymbol> define_udts_table(PdbSession& session) {
    return generator_table<CachedSymbol>("udts")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagUDT)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagUDT); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

// Enums table
inline GeneratorTableDef<CachedSymbol> define_enums_table(PdbSession& session) {
    return generator_table<CachedSymbol>("enums")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagEnum)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagEnum); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

// Typedefs table
inline GeneratorTableDef<CachedSymbol> define_typedefs_table(PdbSession& session) {
    return generator_table<CachedSymbol>("typedefs")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagTypedef)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagTypedef); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .build();
}

// Compilands table
inline GeneratorTableDef<CachedCompiland> define_compilands_table(PdbSession& session) {
    return generator_table<CachedCompiland>("compilands")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagCompiland)); })
        .generator([&session]() { return std::make_unique<CompilandGenerator>(session); })
        .column_int64("id", [](const CachedCompiland& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedCompiland& r) { return r.name; })
        .column_text("library", [](const CachedCompiland& r) { return r.library_name; })
        .column_int("language", [](const CachedCompiland& r) { return static_cast<int>(r.language); })
        .build();
}

// Source files table
inline GeneratorTableDef<CachedSourceFile> define_source_files_table(PdbSession& session) {
    return generator_table<CachedSourceFile>("source_files")
        .estimate_rows([]() { return static_cast<size_t>(1000); })
        .generator([&session]() { return std::make_unique<SourceFileGenerator>(session); })
        .column_int64("id", [](const CachedSourceFile& r) { return static_cast<int64_t>(r.id); })
        .column_text("filename", [](const CachedSourceFile& r) { return r.filename; })
        .column_int("checksum_type", [](const CachedSourceFile& r) { return static_cast<int>(r.checksum_type); })
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
        .estimate_rows([]() { return static_cast<size_t>(128); })
        .generator([&session]() { return std::make_unique<SectionGenerator>(session); })
        .column_int("number", [](const CachedSection& r) { return static_cast<int>(r.section_number); })
        .column_int64("rva", [](const CachedSection& r) { return static_cast<int64_t>(r.rva); })
        .column_int("length", [](const CachedSection& r) { return static_cast<int>(r.length); })
        .column_int("characteristics", [](const CachedSection& r) { return static_cast<int>(r.characteristics); })
        .column_int("readable", [](const CachedSection& r) { return r.read ? 1 : 0; })
        .column_int("writable", [](const CachedSection& r) { return r.write ? 1 : 0; })
        .column_int("executable", [](const CachedSection& r) { return r.execute ? 1 : 0; })
        .column_int("code", [](const CachedSection& r) { return r.code ? 1 : 0; })
        .build();
}

// Thunks table
inline GeneratorTableDef<CachedSymbol> define_thunks_table(PdbSession& session) {
    return generator_table<CachedSymbol>("thunks")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagThunk)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagThunk); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int64("length", [](const CachedSymbol& r) { return static_cast<int64_t>(r.length); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .build();
}

// Labels table
inline GeneratorTableDef<CachedSymbol> define_labels_table(PdbSession& session) {
    return generator_table<CachedSymbol>("labels")
        .estimate_rows([&session]() { return to_size_t_clamped(session.count_symbols(SymTagLabel)); })
        .generator([&session]() { return std::make_unique<SymbolGenerator>(session, SymTagLabel); })
        .column_int64("id", [](const CachedSymbol& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedSymbol& r) { return r.name; })
        .column_int64("rva", [](const CachedSymbol& r) { return static_cast<int64_t>(r.rva); })
        .column_int("section", [](const CachedSymbol& r) { return static_cast<int>(r.section); })
        .column_int("offset", [](const CachedSymbol& r) { return static_cast<int>(r.offset); })
        .build();
}

// UDT members table
inline GeneratorTableDef<CachedMember> define_udt_members_table(PdbSession& session) {
    return generator_table<CachedMember>("udt_members")
        .estimate_rows([]() { return static_cast<size_t>(100000); })
        .generator([&session]() { return std::make_unique<MemberGenerator>(session); })
        .column_int64("udt_id", [](const CachedMember& r) { return static_cast<int64_t>(r.parent_id); })
        .column_text("udt_name", [](const CachedMember& r) { return r.parent_name; })
        .column_int64("id", [](const CachedMember& r) { return static_cast<int64_t>(r.id); })
        .column_text("name", [](const CachedMember& r) { return r.name; })
        .column_text("type", [](const CachedMember& r) { return r.type_name; })
        .column_int("offset", [](const CachedMember& r) { return static_cast<int>(r.offset); })
        .column_int64("length", [](const CachedMember& r) { return static_cast<int64_t>(r.length); })
        .column_int("access", [](const CachedMember& r) { return static_cast<int>(r.access); })
        .column_int("is_static", [](const CachedMember& r) { return r.is_static ? 1 : 0; })
        .column_int("is_virtual", [](const CachedMember& r) { return r.is_virtual ? 1 : 0; })
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
        .column_int("access", [](const CachedBaseClass& r) { return static_cast<int>(r.access); })
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
        .column_int("location_type", [](const CachedLocal& r) { return static_cast<int>(r.location_type); })
        .column_int64("offset_or_register", [](const CachedLocal& r) { return r.offset_or_register; })
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
        .column_text("name", [](const CachedLocal& r) { return r.name; })
        .column_text("type", [](const CachedLocal& r) { return r.type_name; })
        .column_int("location_type", [](const CachedLocal& r) { return static_cast<int>(r.location_type); })
        .column_int64("offset_or_register", [](const CachedLocal& r) { return r.offset_or_register; })
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
    GeneratorTableDef<CachedSymbol> enums_;
    GeneratorTableDef<CachedSymbol> typedefs_;
    GeneratorTableDef<CachedSymbol> thunks_;
    GeneratorTableDef<CachedSymbol> labels_;

    GeneratorTableDef<CachedCompiland> compilands_;
    GeneratorTableDef<CachedSourceFile> source_files_;
    GeneratorTableDef<CachedLineNumber> line_numbers_;

    GeneratorTableDef<CachedSection> sections_;

    GeneratorTableDef<CachedMember> udt_members_;
    GeneratorTableDef<CachedEnumValue> enum_values_;
    GeneratorTableDef<CachedBaseClass> base_classes_;

    GeneratorTableDef<CachedLocal> locals_;
    GeneratorTableDef<CachedLocal> parameters_;

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
        , enums_(define_enums_table(session_))
        , typedefs_(define_typedefs_table(session_))
        , thunks_(define_thunks_table(session_))
        , labels_(define_labels_table(session_))
        , compilands_(define_compilands_table(session_))
        , source_files_(define_source_files_table(session_))
        , line_numbers_(define_line_numbers_table(session_))
        , sections_(define_sections_table(session_))
        , udt_members_(define_udt_members_table(session_))
        , enum_values_(define_enum_values_table(session_))
        , base_classes_(define_base_classes_table(session_))
        , locals_(define_locals_table(session_))
        , parameters_(define_parameters_table(session_))
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

        add_name_and_id_filters(udts_, SymTagUDT);
        add_name_and_id_filters(enums_, SymTagEnum);
        add_name_and_id_filters(typedefs_, SymTagTypedef);
        add_name_and_id_filters(thunks_, SymTagThunk);
        add_name_and_id_filters(labels_, SymTagLabel);

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

        auto* udt_members_def = &udt_members_;
        add_filter_eq(udt_members_, "udt_id",
                      [udt_members_def, this](int64_t id) -> std::unique_ptr<xsql::RowIterator> {
                          if (id <= 0 || id > 0xFFFFFFFFLL) {
                              return std::make_unique<GeneratorRowIterator<CachedMember>>(udt_members_def, nullptr);
                          }
                          return std::make_unique<GeneratorRowIterator<CachedMember>>(
                              udt_members_def,
                              std::make_unique<UdtMembersByIdGenerator>(session_, static_cast<DWORD>(id)));
                      },
                      10.0, 100.0);
        add_filter_eq_text(udt_members_, "udt_name",
                           [udt_members_def, this](const char* name) -> std::unique_ptr<xsql::RowIterator> {
                               return std::make_unique<GeneratorRowIterator<CachedMember>>(
                                   udt_members_def,
                                   std::make_unique<UdtMembersByNameGenerator>(session_, name ? name : ""));
                           },
                           10.0, 100.0);

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
        register_one(db, enums_);
        register_one(db, typedefs_);
        register_one(db, thunks_);
        register_one(db, labels_);

        register_one(db, compilands_);
        register_one(db, source_files_);
        register_one(db, line_numbers_);

        register_one(db, sections_);

        register_one(db, udt_members_);
        register_one(db, enum_values_);
        register_one(db, base_classes_);

        register_one(db, locals_);
        register_one(db, parameters_);
    }
};

} // namespace pdbsql
