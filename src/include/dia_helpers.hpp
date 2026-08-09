// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once
// dia_helpers.hpp - MSDIA RAII wrappers and utilities

#include <atlbase.h>
#include <dia2.h>
#include <string>
#include <stdexcept>
#include <vector>

namespace pdbsql {

// ============================================================================
// COM initialization RAII
// ============================================================================

class ComInit {
    bool initialized_ = false;
public:
    ComInit() {
        HRESULT hr = CoInitialize(nullptr);
        initialized_ = SUCCEEDED(hr);
    }
    ~ComInit() {
        if (initialized_) CoUninitialize();
    }
    bool ok() const { return initialized_; }

    ComInit(const ComInit&) = delete;
    ComInit& operator=(const ComInit&) = delete;
};

// ============================================================================
// BSTR utilities
// ============================================================================

// Convert BSTR to std::string (UTF-8)
inline std::string bstr_to_string(BSTR bstr) {
    if (!bstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, bstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, bstr, -1, result.data(), len, nullptr, nullptr);
    return result;
}

// Convert std::string to wide string
inline std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring result(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, result.data(), len);
    return result;
}

// RAII wrapper for BSTR with auto-free
class SafeBSTR {
    BSTR bstr_ = nullptr;
public:
    SafeBSTR() = default;
    ~SafeBSTR() { if (bstr_) SysFreeString(bstr_); }

    BSTR* ptr() { return &bstr_; }
    BSTR get() const { return bstr_; }
    BSTR bstr() const { return bstr_; }  // Alias for compatibility
    std::string str() const { return bstr_to_string(bstr_); }
    bool empty() const { return !bstr_ || SysStringLen(bstr_) == 0; }

    SafeBSTR(const SafeBSTR&) = delete;
    SafeBSTR& operator=(const SafeBSTR&) = delete;
};

// ============================================================================
// SymTag enum to string
// ============================================================================

inline const char* symtag_to_string(enum SymTagEnum tag) {
    switch (tag) {
        case SymTagNull: return "Null";
        case SymTagExe: return "Exe";
        case SymTagCompiland: return "Compiland";
        case SymTagCompilandDetails: return "CompilandDetails";
        case SymTagCompilandEnv: return "CompilandEnv";
        case SymTagFunction: return "Function";
        case SymTagBlock: return "Block";
        case SymTagData: return "Data";
        case SymTagAnnotation: return "Annotation";
        case SymTagLabel: return "Label";
        case SymTagPublicSymbol: return "PublicSymbol";
        case SymTagUDT: return "UDT";
        case SymTagEnum: return "Enum";
        case SymTagFunctionType: return "FunctionType";
        case SymTagPointerType: return "PointerType";
        case SymTagArrayType: return "ArrayType";
        case SymTagBaseType: return "BaseType";
        case SymTagTypedef: return "Typedef";
        case SymTagBaseClass: return "BaseClass";
        case SymTagFriend: return "Friend";
        case SymTagFunctionArgType: return "FunctionArgType";
        case SymTagFuncDebugStart: return "FuncDebugStart";
        case SymTagFuncDebugEnd: return "FuncDebugEnd";
        case SymTagUsingNamespace: return "UsingNamespace";
        case SymTagVTableShape: return "VTableShape";
        case SymTagVTable: return "VTable";
        case SymTagCustom: return "Custom";
        case SymTagThunk: return "Thunk";
        case SymTagCustomType: return "CustomType";
        case SymTagManagedType: return "ManagedType";
        case SymTagDimension: return "Dimension";
        default: return "Unknown";
    }
}

// ============================================================================
// Error handling
// ============================================================================

inline std::string hresult_to_string(HRESULT hr) {
    char buf[64];
    snprintf(buf, sizeof(buf), "HRESULT 0x%08X", static_cast<unsigned>(hr));
    return buf;
}

class DiaError : public std::runtime_error {
public:
    DiaError(const std::string& msg, HRESULT hr = S_OK)
        : std::runtime_error(hr != S_OK ? msg + " (" + hresult_to_string(hr) + ")" : msg)
        , hr_(hr) {}
    HRESULT hresult() const { return hr_; }
private:
    HRESULT hr_;
};

// Turn a loadDataFromPdb HRESULT into something a user can act on. DIA returns a
// distinct E_PDB_* code per cause, but they all used to surface as one generic
// string, so "DIA isn't registered" and "this file isn't a DIA-readable PDB" were
// indistinguishable from the outside.
inline std::string describe_pdb_load_error(HRESULT hr) {
    switch (hr) {
        case E_PDB_NOT_FOUND:
            return "file not found or inaccessible";
        case E_PDB_FORMAT:
        case E_PDB_V1_PDB:
            return "not a DIA-readable PDB -- DIA reads only MSVC-emitted PDBs; "
                   "PDBs written by LLVM/clang (and other non-MSVC toolchains) are unsupported";
        case E_PDB_INVALID_SIG:
        case E_PDB_INVALID_AGE:
            return "PDB signature/age mismatch (stale or mismatched symbols)";
        case E_PDB_CORRUPT:
            return "PDB is corrupt";
        case E_PDB_ACCESS_DENIED:
            return "access denied reading the PDB";
        case E_PDB_OUT_OF_MEMORY:
            return "out of memory loading the PDB";
        case E_INVALIDARG:
            return "invalid path";
        default:
            return "unrecognized PDB (DIA reads only MSVC-emitted PDBs)";
    }
}

// ============================================================================
// DIA activation
// ============================================================================
//
// Creating the DIA data source normally needs msdia140.dll COM-registered, which
// requires admin and is absent on plenty of machines that DO have the SDK. When
// CoCreateInstance reports the class is not registered we fall back to
// registration-free activation: load the DLL directly and go through its
// DllGetClassObject. CoCreateInstance is still tried FIRST so a properly
// registered machine keeps using exactly the runtime it has always used.

inline std::vector<std::wstring> dia_module_candidates() {
    std::vector<std::wstring> out;
#if defined(_M_X64) || defined(_M_ARM64)
    const wchar_t* arch_sub = L"bin\\amd64\\";
#else
    const wchar_t* arch_sub = L"bin\\";
#endif

    // 1. Next to our own executable (a DLL shipped alongside the tool wins).
    {
        wchar_t exe[MAX_PATH] = {};
        if (GetModuleFileNameW(nullptr, exe, MAX_PATH)) {
            std::wstring p(exe);
            const size_t slash = p.find_last_of(L"\\/");
            if (slash != std::wstring::npos) out.push_back(p.substr(0, slash + 1) + L"msdia140.dll");
        }
    }

    // 2. The SDK location the active developer environment points at.
    auto from_env = [&](const wchar_t* var, const wchar_t* suffix) {
        wchar_t buf[32768];
        const DWORD n = GetEnvironmentVariableW(var, buf, 32768);
        if (n > 0 && n < 32768) {
            std::wstring p(buf, n);
            if (!p.empty() && p.back() != L'\\' && p.back() != L'/') p += L'\\';
            out.push_back(p + suffix + arch_sub + L"msdia140.dll");
        }
    };
    from_env(L"VSINSTALLDIR", L"DIA SDK\\");
    from_env(L"VCINSTALLDIR", L"..\\DIA SDK\\");

    // 3. Installed Visual Studios: <root>\<year>\<edition>\DIA SDK\bin\...
    const wchar_t* roots[] = {
        L"C:\\Program Files\\Microsoft Visual Studio\\",
        L"C:\\Program Files (x86)\\Microsoft Visual Studio\\",
    };
    for (const wchar_t* root : roots) {
        WIN32_FIND_DATAW yd = {};
        HANDLE yh = FindFirstFileW((std::wstring(root) + L"*").c_str(), &yd);
        if (yh == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(yd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (yd.cFileName[0] == L'.') continue;
            const std::wstring year = std::wstring(root) + yd.cFileName + L"\\";
            WIN32_FIND_DATAW ed = {};
            HANDLE eh = FindFirstFileW((year + L"*").c_str(), &ed);
            if (eh == INVALID_HANDLE_VALUE) continue;
            do {
                if (!(ed.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (ed.cFileName[0] == L'.') continue;
                out.push_back(year + ed.cFileName + L"\\DIA SDK\\" + arch_sub + L"msdia140.dll");
            } while (FindNextFileW(eh, &ed));
            FindClose(eh);
        } while (FindNextFileW(yh, &yd));
        FindClose(yh);
    }
    return out;
}

// Registration-free CoCreateInstance equivalent. `loaded_from` receives the DLL
// path that worked, for diagnostics. The module handle is deliberately never
// freed: the returned COM object outlives this call, and unloading msdia while it
// is live would crash. It is process-lifetime by design.
inline HRESULT create_dia_source_regfree(CComPtr<IDiaDataSource>& out, std::wstring* loaded_from = nullptr) {
    using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);
    HRESULT last = REGDB_E_CLASSNOTREG;

    for (const std::wstring& path : dia_module_candidates()) {
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) continue;

        HMODULE mod = LoadLibraryW(path.c_str());
        if (!mod) { last = HRESULT_FROM_WIN32(GetLastError()); continue; }

        auto get_class_object =
            reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(mod, "DllGetClassObject"));
        if (!get_class_object) { last = E_NOINTERFACE; continue; }

        CComPtr<IClassFactory> factory;
        last = get_class_object(CLSID_DiaSource, IID_IClassFactory, reinterpret_cast<void**>(&factory));
        if (FAILED(last) || !factory) continue;

        CComPtr<IDiaDataSource> source;
        last = factory->CreateInstance(nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(&source));
        if (SUCCEEDED(last) && source) {
            if (loaded_from) *loaded_from = path;
            out = source;
            return S_OK;
        }
    }
    return last;
}

} // namespace pdbsql
