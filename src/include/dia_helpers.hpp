#pragma once
// dia_helpers.hpp - MSDIA RAII wrappers and utilities

#include <atlbase.h>
#include <dia2.h>
#include <string>
#include <stdexcept>

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

} // namespace pdbsql
