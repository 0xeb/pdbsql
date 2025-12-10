#pragma once
/**
 * pdb_tables.hpp - PDB entity virtual tables
 *
 * Defines virtual tables for PDB symbols using the xsql vtable framework.
 * Tables use cached symbol data for efficient repeated queries.
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
#include "pdb_session.hpp"
#include <vector>
#include <memory>
#include <unordered_map>

namespace pdbsql {

// Import xsql types into pdbsql namespace for convenience
using xsql::VTableDef;
using xsql::VTableBuilder;
using xsql::ColumnDef;
using xsql::ColumnType;
using xsql::table;
using xsql::register_vtable;
using xsql::create_vtable;

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
// Global Caches
// ============================================================================

// Symbol caches by SymTag
inline std::vector<CachedSymbol>& get_symbol_cache(enum SymTagEnum tag) {
    static std::vector<CachedSymbol> function_cache;
    static std::vector<CachedSymbol> public_cache;
    static std::vector<CachedSymbol> data_cache;
    static std::vector<CachedSymbol> udt_cache;
    static std::vector<CachedSymbol> enum_cache;
    static std::vector<CachedSymbol> typedef_cache;
    static std::vector<CachedSymbol> thunk_cache;
    static std::vector<CachedSymbol> label_cache;
    static std::vector<CachedSymbol> all_cache;

    switch (tag) {
        case SymTagFunction: return function_cache;
        case SymTagPublicSymbol: return public_cache;
        case SymTagData: return data_cache;
        case SymTagUDT: return udt_cache;
        case SymTagEnum: return enum_cache;
        case SymTagTypedef: return typedef_cache;
        case SymTagThunk: return thunk_cache;
        case SymTagLabel: return label_cache;
        default: return all_cache;
    }
}

inline std::vector<CachedCompiland>& get_compiland_cache() {
    static std::vector<CachedCompiland> cache;
    return cache;
}

inline std::vector<CachedSourceFile>& get_source_file_cache() {
    static std::vector<CachedSourceFile> cache;
    return cache;
}

inline std::vector<CachedLineNumber>& get_line_number_cache() {
    static std::vector<CachedLineNumber> cache;
    return cache;
}

inline std::vector<CachedSection>& get_section_cache() {
    static std::vector<CachedSection> cache;
    return cache;
}

inline std::vector<CachedMember>& get_member_cache() {
    static std::vector<CachedMember> cache;
    return cache;
}

inline std::vector<CachedEnumValue>& get_enum_value_cache() {
    static std::vector<CachedEnumValue> cache;
    return cache;
}

inline std::vector<CachedBaseClass>& get_base_class_cache() {
    static std::vector<CachedBaseClass> cache;
    return cache;
}

inline std::vector<CachedLocal>& get_local_cache() {
    static std::vector<CachedLocal> cache;
    return cache;
}

inline std::vector<CachedLocal>& get_parameter_cache() {
    static std::vector<CachedLocal> cache;
    return cache;
}

// ============================================================================
// Cache Rebuild Functions
// ============================================================================

inline void rebuild_symbol_cache(PdbSession& session, enum SymTagEnum tag) {
    auto& cache = get_symbol_cache(tag);
    cache.clear();

    auto symbols = session.enum_symbols(tag);
    if (!symbols) return;

    CComPtr<IDiaSymbol> symbol;
    ULONG fetched = 0;

    while (SUCCEEDED(symbols->Next(1, &symbol, &fetched)) && fetched == 1) {
        CachedSymbol cs;
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

        cache.push_back(std::move(cs));
        symbol.Release();
    }
}

inline void rebuild_compiland_cache(PdbSession& session) {
    auto& cache = get_compiland_cache();
    cache.clear();

    auto symbols = session.enum_symbols(SymTagCompiland);
    if (!symbols) return;

    CComPtr<IDiaSymbol> symbol;
    ULONG fetched = 0;

    while (SUCCEEDED(symbols->Next(1, &symbol, &fetched)) && fetched == 1) {
        CachedCompiland cc;
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

        cache.push_back(std::move(cc));
        symbol.Release();
    }
}

inline void rebuild_source_file_cache(PdbSession& session) {
    auto& cache = get_source_file_cache();
    cache.clear();

    auto dia_session = session.session();
    if (!dia_session) return;

    CComPtr<IDiaEnumSourceFiles> source_files;
    if (FAILED(dia_session->findFile(nullptr, nullptr, nsNone, &source_files))) return;
    if (!source_files) return;

    CComPtr<IDiaSourceFile> file;
    ULONG fetched = 0;

    while (SUCCEEDED(source_files->Next(1, &file, &fetched)) && fetched == 1) {
        CachedSourceFile sf;
        file->get_uniqueId(&sf.id);

        SafeBSTR filename;
        if (SUCCEEDED(file->get_fileName(filename.ptr()))) {
            sf.filename = filename.str();
        }

        file->get_checksumType(&sf.checksum_type);

        cache.push_back(std::move(sf));
        file.Release();
    }
}

inline void rebuild_line_number_cache(PdbSession& session) {
    auto& cache = get_line_number_cache();
    cache.clear();

    auto dia_session = session.session();
    if (!dia_session) return;

    // Enumerate all line numbers by iterating compilands
    auto compilands = session.enum_symbols(SymTagCompiland);
    if (!compilands) return;

    CComPtr<IDiaSymbol> compiland;
    ULONG cfetched = 0;

    while (SUCCEEDED(compilands->Next(1, &compiland, &cfetched)) && cfetched == 1) {
        DWORD compiland_id = 0;
        compiland->get_symIndexId(&compiland_id);

        // Get source files for this compiland
        CComPtr<IDiaEnumSourceFiles> source_files;
        if (SUCCEEDED(dia_session->findFile(compiland, nullptr, nsNone, &source_files)) && source_files) {
            CComPtr<IDiaSourceFile> file;
            ULONG ffetched = 0;

            while (SUCCEEDED(source_files->Next(1, &file, &ffetched)) && ffetched == 1) {
                CComPtr<IDiaEnumLineNumbers> lines;
                if (SUCCEEDED(dia_session->findLines(compiland, file, &lines)) && lines) {
                    CComPtr<IDiaLineNumber> line;
                    ULONG lfetched = 0;

                    while (SUCCEEDED(lines->Next(1, &line, &lfetched)) && lfetched == 1) {
                        CachedLineNumber ln;
                        line->get_sourceFileId(&ln.file_id);
                        line->get_lineNumber(&ln.line);
                        line->get_columnNumber(&ln.column);
                        line->get_relativeVirtualAddress(&ln.rva);
                        line->get_length(&ln.length);
                        ln.compiland_id = compiland_id;

                        cache.push_back(std::move(ln));
                        line.Release();
                    }
                }
                file.Release();
            }
        }
        compiland.Release();
    }
}

inline void rebuild_section_cache(PdbSession& session) {
    auto& cache = get_section_cache();
    cache.clear();

    auto dia_session = session.session();
    if (!dia_session) return;

    CComPtr<IDiaEnumSectionContribs> contribs;
    CComPtr<IDiaEnumTables> tables;
    if (FAILED(dia_session->getEnumTables(&tables)) || !tables) return;

    // Find section contributions table
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

    // Collect unique sections
    std::unordered_map<DWORD, CachedSection> sections;

    CComPtr<IDiaSectionContrib> contrib;
    ULONG cfetched = 0;
    while (SUCCEEDED(contribs->Next(1, &contrib, &cfetched)) && cfetched == 1) {
        DWORD sec_num = 0;
        contrib->get_addressSection(&sec_num);

        if (sections.find(sec_num) == sections.end()) {
            CachedSection cs;
            cs.section_number = sec_num;

            DWORD rva = 0, len = 0;
            contrib->get_relativeVirtualAddress(&rva);
            contrib->get_length(&len);

            cs.rva = rva;
            cs.length = len;

            // Get boolean properties directly from IDiaSectionContrib
            BOOL val = FALSE;
            if (SUCCEEDED(contrib->get_read(&val))) cs.read = (val != FALSE);
            if (SUCCEEDED(contrib->get_write(&val))) cs.write = (val != FALSE);
            if (SUCCEEDED(contrib->get_execute(&val))) cs.execute = (val != FALSE);
            if (SUCCEEDED(contrib->get_code(&val))) cs.code = (val != FALSE);

            sections[sec_num] = cs;
        } else {
            // Extend section bounds
            DWORD rva = 0, len = 0;
            contrib->get_relativeVirtualAddress(&rva);
            contrib->get_length(&len);

            auto& s = sections[sec_num];
            DWORD end = rva + len;
            DWORD cur_end = s.rva + s.length;
            if (end > cur_end) {
                s.length = end - s.rva;
            }
        }
        contrib.Release();
    }

    for (auto& [num, sec] : sections) {
        cache.push_back(sec);
    }
}

inline void rebuild_member_cache(PdbSession& session) {
    auto& cache = get_member_cache();
    cache.clear();

    // Enumerate all UDTs and their members
    auto udts = session.enum_symbols(SymTagUDT);
    if (!udts) return;

    CComPtr<IDiaSymbol> udt;
    ULONG ufetched = 0;

    while (SUCCEEDED(udts->Next(1, &udt, &ufetched)) && ufetched == 1) {
        DWORD parent_id = 0;
        std::string parent_name;

        udt->get_symIndexId(&parent_id);
        SafeBSTR pname;
        if (SUCCEEDED(udt->get_name(pname.ptr()))) {
            parent_name = pname.str();
        }

        // Get members (SymTagData children of UDT)
        CComPtr<IDiaEnumSymbols> members;
        if (SUCCEEDED(udt->findChildren(SymTagData, nullptr, nsNone, &members)) && members) {
            CComPtr<IDiaSymbol> member;
            ULONG mfetched = 0;

            while (SUCCEEDED(members->Next(1, &member, &mfetched)) && mfetched == 1) {
                CachedMember cm;
                cm.parent_id = parent_id;
                cm.parent_name = parent_name;

                member->get_symIndexId(&cm.id);

                SafeBSTR mname;
                if (SUCCEEDED(member->get_name(mname.ptr()))) {
                    cm.name = mname.str();
                }

                // Get type
                CComPtr<IDiaSymbol> type;
                if (SUCCEEDED(member->get_type(&type)) && type) {
                    SafeBSTR tname;
                    if (SUCCEEDED(type->get_name(tname.ptr()))) {
                        cm.type_name = tname.str();
                    }
                    ULONGLONG len = 0;
                    type->get_length(&len);
                    cm.length = len;
                }

                LONG offset = 0;
                member->get_offset(&offset);
                cm.offset = static_cast<DWORD>(offset);

                DWORD access = 0;
                member->get_access(&access);
                cm.access = access;

                DWORD loc_type = 0;
                member->get_locationType(&loc_type);
                cm.is_static = (loc_type == LocIsStatic);

                BOOL virt = FALSE;
                member->get_virtual(&virt);
                cm.is_virtual = (virt != FALSE);

                cache.push_back(std::move(cm));
                member.Release();
            }
        }
        udt.Release();
    }
}

inline void rebuild_enum_value_cache(PdbSession& session) {
    auto& cache = get_enum_value_cache();
    cache.clear();

    auto enums = session.enum_symbols(SymTagEnum);
    if (!enums) return;

    CComPtr<IDiaSymbol> enum_sym;
    ULONG efetched = 0;

    while (SUCCEEDED(enums->Next(1, &enum_sym, &efetched)) && efetched == 1) {
        DWORD enum_id = 0;
        std::string enum_name;

        enum_sym->get_symIndexId(&enum_id);
        SafeBSTR ename;
        if (SUCCEEDED(enum_sym->get_name(ename.ptr()))) {
            enum_name = ename.str();
        }

        // Get enum values (SymTagData children)
        CComPtr<IDiaEnumSymbols> values;
        if (SUCCEEDED(enum_sym->findChildren(SymTagData, nullptr, nsNone, &values)) && values) {
            CComPtr<IDiaSymbol> val;
            ULONG vfetched = 0;

            while (SUCCEEDED(values->Next(1, &val, &vfetched)) && vfetched == 1) {
                CachedEnumValue ev;
                ev.enum_id = enum_id;
                ev.enum_name = enum_name;

                val->get_symIndexId(&ev.id);

                SafeBSTR vname;
                if (SUCCEEDED(val->get_name(vname.ptr()))) {
                    ev.name = vname.str();
                }

                VARIANT v = {};
                if (SUCCEEDED(val->get_value(&v))) {
                    switch (v.vt) {
                        case VT_I1: ev.value = v.cVal; break;
                        case VT_I2: ev.value = v.iVal; break;
                        case VT_I4: ev.value = v.lVal; break;
                        case VT_I8: ev.value = v.llVal; break;
                        case VT_UI1: ev.value = v.bVal; break;
                        case VT_UI2: ev.value = v.uiVal; break;
                        case VT_UI4: ev.value = v.ulVal; break;
                        case VT_UI8: ev.value = static_cast<int64_t>(v.ullVal); break;
                        case VT_INT: ev.value = v.intVal; break;
                        case VT_UINT: ev.value = v.uintVal; break;
                        default: break;
                    }
                    VariantClear(&v);
                }

                cache.push_back(std::move(ev));
                val.Release();
            }
        }
        enum_sym.Release();
    }
}

inline void rebuild_base_class_cache(PdbSession& session) {
    auto& cache = get_base_class_cache();
    cache.clear();

    auto udts = session.enum_symbols(SymTagUDT);
    if (!udts) return;

    CComPtr<IDiaSymbol> udt;
    ULONG ufetched = 0;

    while (SUCCEEDED(udts->Next(1, &udt, &ufetched)) && ufetched == 1) {
        DWORD derived_id = 0;
        std::string derived_name;

        udt->get_symIndexId(&derived_id);
        SafeBSTR dname;
        if (SUCCEEDED(udt->get_name(dname.ptr()))) {
            derived_name = dname.str();
        }

        // Get base classes
        CComPtr<IDiaEnumSymbols> bases;
        if (SUCCEEDED(udt->findChildren(SymTagBaseClass, nullptr, nsNone, &bases)) && bases) {
            CComPtr<IDiaSymbol> base;
            ULONG bfetched = 0;

            while (SUCCEEDED(bases->Next(1, &base, &bfetched)) && bfetched == 1) {
                CachedBaseClass bc;
                bc.derived_id = derived_id;
                bc.derived_name = derived_name;

                // Get the base type
                CComPtr<IDiaSymbol> base_type;
                if (SUCCEEDED(base->get_type(&base_type)) && base_type) {
                    base_type->get_symIndexId(&bc.base_id);
                    SafeBSTR bname;
                    if (SUCCEEDED(base_type->get_name(bname.ptr()))) {
                        bc.base_name = bname.str();
                    }
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

                cache.push_back(std::move(bc));
                base.Release();
            }
        }
        udt.Release();
    }
}

inline void rebuild_local_and_param_caches(PdbSession& session) {
    auto& local_cache = get_local_cache();
    auto& param_cache = get_parameter_cache();
    local_cache.clear();
    param_cache.clear();

    auto functions = session.enum_symbols(SymTagFunction);
    if (!functions) return;

    CComPtr<IDiaSymbol> func;
    ULONG ffetched = 0;

    while (SUCCEEDED(functions->Next(1, &func, &ffetched)) && ffetched == 1) {
        DWORD func_id = 0;
        std::string func_name;

        func->get_symIndexId(&func_id);
        SafeBSTR fname;
        if (SUCCEEDED(func->get_name(fname.ptr()))) {
            func_name = fname.str();
        }

        // Get all data children (locals and parameters)
        CComPtr<IDiaEnumSymbols> data_syms;
        if (SUCCEEDED(func->findChildren(SymTagData, nullptr, nsNone, &data_syms)) && data_syms) {
            CComPtr<IDiaSymbol> data;
            ULONG dfetched = 0;

            while (SUCCEEDED(data_syms->Next(1, &data, &dfetched)) && dfetched == 1) {
                CachedLocal cl;
                cl.func_id = func_id;
                cl.func_name = func_name;

                data->get_symIndexId(&cl.id);

                SafeBSTR dname;
                if (SUCCEEDED(data->get_name(dname.ptr()))) {
                    cl.name = dname.str();
                }

                // Get type name
                CComPtr<IDiaSymbol> type;
                if (SUCCEEDED(data->get_type(&type)) && type) {
                    SafeBSTR tname;
                    if (SUCCEEDED(type->get_name(tname.ptr()))) {
                        cl.type_name = tname.str();
                    }
                }

                DWORD loc_type = 0;
                data->get_locationType(&loc_type);
                cl.location_type = loc_type;

                // Get offset or register based on location type
                LONG offset = 0;
                DWORD reg = 0;
                data->get_offset(&offset);
                data->get_registerId(&reg);
                cl.offset_or_register = (loc_type == LocIsRegRel) ? offset : reg;

                // Determine if it's a parameter
                DWORD data_kind = 0;
                data->get_dataKind(&data_kind);

                if (data_kind == DataIsParam) {
                    param_cache.push_back(cl);
                } else if (data_kind == DataIsLocal) {
                    local_cache.push_back(cl);
                }

                data.Release();
            }
        }
        func.Release();
    }
}

// ============================================================================
// Table Definitions
// ============================================================================

// Functions table
inline VTableDef define_functions_table(PdbSession& session) {
    return table("functions")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagFunction);
            return get_symbol_cache(SymTagFunction).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagFunction)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagFunction)[i].name;
        })
        .column_text("undecorated", [](size_t i) {
            return get_symbol_cache(SymTagFunction)[i].undecorated;
        })
        .column_int64("rva", [](size_t i) {
            return get_symbol_cache(SymTagFunction)[i].rva;
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_symbol_cache(SymTagFunction)[i].length);
        })
        .column_int("section", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagFunction)[i].section);
        })
        .column_int("offset", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagFunction)[i].offset);
        })
        .build();
}

// Public symbols table
inline VTableDef define_publics_table(PdbSession& session) {
    return table("publics")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagPublicSymbol);
            return get_symbol_cache(SymTagPublicSymbol).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagPublicSymbol)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagPublicSymbol)[i].name;
        })
        .column_text("undecorated", [](size_t i) {
            return get_symbol_cache(SymTagPublicSymbol)[i].undecorated;
        })
        .column_int64("rva", [](size_t i) {
            return get_symbol_cache(SymTagPublicSymbol)[i].rva;
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_symbol_cache(SymTagPublicSymbol)[i].length);
        })
        .column_int("section", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagPublicSymbol)[i].section);
        })
        .column_int("offset", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagPublicSymbol)[i].offset);
        })
        .build();
}

// Data symbols table
inline VTableDef define_data_table(PdbSession& session) {
    return table("data")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagData);
            return get_symbol_cache(SymTagData).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagData)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagData)[i].name;
        })
        .column_int64("rva", [](size_t i) {
            return get_symbol_cache(SymTagData)[i].rva;
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_symbol_cache(SymTagData)[i].length);
        })
        .column_int("section", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagData)[i].section);
        })
        .column_int("offset", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagData)[i].offset);
        })
        .build();
}

// UDT (structs/classes) table
inline VTableDef define_udts_table(PdbSession& session) {
    return table("udts")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagUDT);
            return get_symbol_cache(SymTagUDT).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagUDT)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagUDT)[i].name;
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_symbol_cache(SymTagUDT)[i].length);
        })
        .build();
}

// Enums table
inline VTableDef define_enums_table(PdbSession& session) {
    return table("enums")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagEnum);
            return get_symbol_cache(SymTagEnum).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagEnum)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagEnum)[i].name;
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_symbol_cache(SymTagEnum)[i].length);
        })
        .build();
}

// Typedefs table
inline VTableDef define_typedefs_table(PdbSession& session) {
    return table("typedefs")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagTypedef);
            return get_symbol_cache(SymTagTypedef).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagTypedef)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagTypedef)[i].name;
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_symbol_cache(SymTagTypedef)[i].length);
        })
        .build();
}

// Compilands table
inline VTableDef define_compilands_table(PdbSession& session) {
    return table("compilands")
        .count([&session]() {
            rebuild_compiland_cache(session);
            return get_compiland_cache().size();
        })
        .column_int64("id", [](size_t i) {
            return get_compiland_cache()[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_compiland_cache()[i].name;
        })
        .column_text("library", [](size_t i) {
            return get_compiland_cache()[i].library_name;
        })
        .column_int("language", [](size_t i) {
            return static_cast<int>(get_compiland_cache()[i].language);
        })
        .build();
}

// Source files table
inline VTableDef define_source_files_table(PdbSession& session) {
    return table("source_files")
        .count([&session]() {
            rebuild_source_file_cache(session);
            return get_source_file_cache().size();
        })
        .column_int64("id", [](size_t i) {
            return get_source_file_cache()[i].id;
        })
        .column_text("filename", [](size_t i) {
            return get_source_file_cache()[i].filename;
        })
        .column_int("checksum_type", [](size_t i) {
            return static_cast<int>(get_source_file_cache()[i].checksum_type);
        })
        .build();
}

// Line numbers table
inline VTableDef define_line_numbers_table(PdbSession& session) {
    return table("line_numbers")
        .count([&session]() {
            rebuild_line_number_cache(session);
            return get_line_number_cache().size();
        })
        .column_int64("file_id", [](size_t i) {
            return get_line_number_cache()[i].file_id;
        })
        .column_int("line", [](size_t i) {
            return static_cast<int>(get_line_number_cache()[i].line);
        })
        .column_int("column", [](size_t i) {
            return static_cast<int>(get_line_number_cache()[i].column);
        })
        .column_int64("rva", [](size_t i) {
            return get_line_number_cache()[i].rva;
        })
        .column_int("length", [](size_t i) {
            return static_cast<int>(get_line_number_cache()[i].length);
        })
        .column_int64("compiland_id", [](size_t i) {
            return get_line_number_cache()[i].compiland_id;
        })
        .build();
}

// Sections table
inline VTableDef define_sections_table(PdbSession& session) {
    return table("sections")
        .count([&session]() {
            rebuild_section_cache(session);
            return get_section_cache().size();
        })
        .column_int("number", [](size_t i) {
            return static_cast<int>(get_section_cache()[i].section_number);
        })
        .column_int64("rva", [](size_t i) {
            return get_section_cache()[i].rva;
        })
        .column_int("length", [](size_t i) {
            return static_cast<int>(get_section_cache()[i].length);
        })
        .column_int("characteristics", [](size_t i) {
            return static_cast<int>(get_section_cache()[i].characteristics);
        })
        .column_int("readable", [](size_t i) {
            return get_section_cache()[i].read ? 1 : 0;
        })
        .column_int("writable", [](size_t i) {
            return get_section_cache()[i].write ? 1 : 0;
        })
        .column_int("executable", [](size_t i) {
            return get_section_cache()[i].execute ? 1 : 0;
        })
        .column_int("code", [](size_t i) {
            return get_section_cache()[i].code ? 1 : 0;
        })
        .build();
}

// Thunks table
inline VTableDef define_thunks_table(PdbSession& session) {
    return table("thunks")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagThunk);
            return get_symbol_cache(SymTagThunk).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagThunk)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagThunk)[i].name;
        })
        .column_int64("rva", [](size_t i) {
            return get_symbol_cache(SymTagThunk)[i].rva;
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_symbol_cache(SymTagThunk)[i].length);
        })
        .column_int("section", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagThunk)[i].section);
        })
        .build();
}

// Labels table
inline VTableDef define_labels_table(PdbSession& session) {
    return table("labels")
        .count([&session]() {
            rebuild_symbol_cache(session, SymTagLabel);
            return get_symbol_cache(SymTagLabel).size();
        })
        .column_int64("id", [](size_t i) {
            return get_symbol_cache(SymTagLabel)[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_symbol_cache(SymTagLabel)[i].name;
        })
        .column_int64("rva", [](size_t i) {
            return get_symbol_cache(SymTagLabel)[i].rva;
        })
        .column_int("section", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagLabel)[i].section);
        })
        .column_int("offset", [](size_t i) {
            return static_cast<int>(get_symbol_cache(SymTagLabel)[i].offset);
        })
        .build();
}

// UDT members table
inline VTableDef define_udt_members_table(PdbSession& session) {
    return table("udt_members")
        .count([&session]() {
            rebuild_member_cache(session);
            return get_member_cache().size();
        })
        .column_int64("udt_id", [](size_t i) {
            return get_member_cache()[i].parent_id;
        })
        .column_text("udt_name", [](size_t i) {
            return get_member_cache()[i].parent_name;
        })
        .column_int64("id", [](size_t i) {
            return get_member_cache()[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_member_cache()[i].name;
        })
        .column_text("type", [](size_t i) {
            return get_member_cache()[i].type_name;
        })
        .column_int("offset", [](size_t i) {
            return static_cast<int>(get_member_cache()[i].offset);
        })
        .column_int64("length", [](size_t i) {
            return static_cast<int64_t>(get_member_cache()[i].length);
        })
        .column_int("access", [](size_t i) {
            return static_cast<int>(get_member_cache()[i].access);
        })
        .column_int("is_static", [](size_t i) {
            return get_member_cache()[i].is_static ? 1 : 0;
        })
        .column_int("is_virtual", [](size_t i) {
            return get_member_cache()[i].is_virtual ? 1 : 0;
        })
        .build();
}

// Enum values table
inline VTableDef define_enum_values_table(PdbSession& session) {
    return table("enum_values")
        .count([&session]() {
            rebuild_enum_value_cache(session);
            return get_enum_value_cache().size();
        })
        .column_int64("enum_id", [](size_t i) {
            return get_enum_value_cache()[i].enum_id;
        })
        .column_text("enum_name", [](size_t i) {
            return get_enum_value_cache()[i].enum_name;
        })
        .column_int64("id", [](size_t i) {
            return get_enum_value_cache()[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_enum_value_cache()[i].name;
        })
        .column_int64("value", [](size_t i) {
            return get_enum_value_cache()[i].value;
        })
        .build();
}

// Base classes table
inline VTableDef define_base_classes_table(PdbSession& session) {
    return table("base_classes")
        .count([&session]() {
            rebuild_base_class_cache(session);
            return get_base_class_cache().size();
        })
        .column_int64("derived_id", [](size_t i) {
            return get_base_class_cache()[i].derived_id;
        })
        .column_text("derived_name", [](size_t i) {
            return get_base_class_cache()[i].derived_name;
        })
        .column_int64("base_id", [](size_t i) {
            return get_base_class_cache()[i].base_id;
        })
        .column_text("base_name", [](size_t i) {
            return get_base_class_cache()[i].base_name;
        })
        .column_int("offset", [](size_t i) {
            return static_cast<int>(get_base_class_cache()[i].offset);
        })
        .column_int("is_virtual", [](size_t i) {
            return get_base_class_cache()[i].is_virtual ? 1 : 0;
        })
        .column_int("access", [](size_t i) {
            return static_cast<int>(get_base_class_cache()[i].access);
        })
        .build();
}

// Locals table
inline VTableDef define_locals_table(PdbSession& session) {
    return table("locals")
        .count([&session]() {
            rebuild_local_and_param_caches(session);
            return get_local_cache().size();
        })
        .column_int64("func_id", [](size_t i) {
            return get_local_cache()[i].func_id;
        })
        .column_text("func_name", [](size_t i) {
            return get_local_cache()[i].func_name;
        })
        .column_int64("id", [](size_t i) {
            return get_local_cache()[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_local_cache()[i].name;
        })
        .column_text("type", [](size_t i) {
            return get_local_cache()[i].type_name;
        })
        .column_int("location_type", [](size_t i) {
            return static_cast<int>(get_local_cache()[i].location_type);
        })
        .column_int64("offset_or_register", [](size_t i) {
            return get_local_cache()[i].offset_or_register;
        })
        .build();
}

// Parameters table
inline VTableDef define_parameters_table(PdbSession& session) {
    return table("parameters")
        .count([&session]() {
            rebuild_local_and_param_caches(session);
            return get_parameter_cache().size();
        })
        .column_int64("func_id", [](size_t i) {
            return get_parameter_cache()[i].func_id;
        })
        .column_text("func_name", [](size_t i) {
            return get_parameter_cache()[i].func_name;
        })
        .column_int64("id", [](size_t i) {
            return get_parameter_cache()[i].id;
        })
        .column_text("name", [](size_t i) {
            return get_parameter_cache()[i].name;
        })
        .column_text("type", [](size_t i) {
            return get_parameter_cache()[i].type_name;
        })
        .column_int("location_type", [](size_t i) {
            return static_cast<int>(get_parameter_cache()[i].location_type);
        })
        .column_int64("offset_or_register", [](size_t i) {
            return get_parameter_cache()[i].offset_or_register;
        })
        .build();
}

// ============================================================================
// Table Registry
// ============================================================================

class TableRegistry {
    std::vector<VTableDef> defs_;
    PdbSession& session_;

public:
    explicit TableRegistry(PdbSession& session) : session_(session) {}

    void register_all(sqlite3* db) {
        // Core symbol tables
        defs_.push_back(define_functions_table(session_));
        defs_.push_back(define_publics_table(session_));
        defs_.push_back(define_data_table(session_));
        defs_.push_back(define_udts_table(session_));
        defs_.push_back(define_enums_table(session_));
        defs_.push_back(define_typedefs_table(session_));
        defs_.push_back(define_thunks_table(session_));
        defs_.push_back(define_labels_table(session_));

        // Compilation unit tables
        defs_.push_back(define_compilands_table(session_));
        defs_.push_back(define_source_files_table(session_));
        defs_.push_back(define_line_numbers_table(session_));

        // Structure tables
        defs_.push_back(define_sections_table(session_));

        // Type hierarchy tables
        defs_.push_back(define_udt_members_table(session_));
        defs_.push_back(define_enum_values_table(session_));
        defs_.push_back(define_base_classes_table(session_));

        // Function detail tables
        defs_.push_back(define_locals_table(session_));
        defs_.push_back(define_parameters_table(session_));

        // Register and create each table
        for (auto& def : defs_) {
            std::string module_name = "pdb_" + def.name;
            register_vtable(db, module_name.c_str(), &def);
            create_vtable(db, def.name.c_str(), module_name.c_str());
        }
    }
};

} // namespace pdbsql
