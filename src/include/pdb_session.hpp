#pragma once
// pdb_session.hpp - PDB file session management

#include "dia_helpers.hpp"
#include <memory>

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

        // Create DiaDataSource
        HRESULT hr = source_.CoCreateInstance(CLSID_DiaSource);
        if (FAILED(hr)) {
            last_error_ = "Failed to create DiaSource";
            return false;
        }

        // Load PDB
        std::wstring wpath = string_to_wstring(pdb_path);
        hr = source_->loadDataFromPdb(wpath.c_str());
        if (FAILED(hr)) {
            last_error_ = "Failed to load PDB: " + pdb_path;
            return false;
        }

        // Open session
        hr = source_->openSession(&session_);
        if (FAILED(hr)) {
            last_error_ = "Failed to open session";
            return false;
        }

        // Get global scope
        hr = session_->get_globalScope(&global_);
        if (FAILED(hr)) {
            last_error_ = "Failed to get global scope";
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

    // Get symbol count for a type
    LONG count_symbols(enum SymTagEnum symtag) {
        auto symbols = enum_symbols(symtag);
        if (!symbols) return 0;
        LONG count = 0;
        symbols->get_Count(&count);
        return count;
    }

private:
    ComInit com_;  // Must be first - initializes COM
    CComPtr<IDiaDataSource> source_;
    CComPtr<IDiaSession> session_;
    CComPtr<IDiaSymbol> global_;
    std::string path_;
    std::string last_error_;
};

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
