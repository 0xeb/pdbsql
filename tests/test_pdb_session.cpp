// test_pdb_session.cpp - Tests for PdbSession functionality

#include <gtest/gtest.h>
#include "pdb_session.hpp"

class PdbSessionTest : public ::testing::Test {
protected:
    pdbsql::ComInit com_init_;
    pdbsql::PdbSession session_;

    void SetUp() override {
        ASSERT_TRUE(com_init_.ok()) << "COM initialization failed";
        ASSERT_TRUE(session_.open(TEST_PDB_PATH)) << session_.last_error();
    }
};

TEST_F(PdbSessionTest, OpenValidPdb) {
    // Session was opened in SetUp
    EXPECT_TRUE(session_.global() != nullptr);
    EXPECT_TRUE(session_.session() != nullptr);
}

TEST_F(PdbSessionTest, OpenInvalidPdb) {
    pdbsql::PdbSession bad_session;
    EXPECT_FALSE(bad_session.open("nonexistent.pdb"));
    EXPECT_FALSE(bad_session.last_error().empty());
}

TEST_F(PdbSessionTest, CountFunctions) {
    LONG count = session_.count_symbols(SymTagFunction);
    // Test program should have at least a few functions
    EXPECT_GT(count, 10) << "Expected at least 10 functions in test PDB";
}

TEST_F(PdbSessionTest, CountPublicSymbols) {
    LONG count = session_.count_symbols(SymTagPublicSymbol);
    EXPECT_GT(count, 0) << "Expected public symbols in test PDB";
}

TEST_F(PdbSessionTest, CountUDTs) {
    LONG count = session_.count_symbols(SymTagUDT);
    // Test program has Counter, Rectangle, etc.
    EXPECT_GT(count, 3) << "Expected at least Counter, Rectangle, Circle, Square";
}

TEST_F(PdbSessionTest, CountEnums) {
    LONG count = session_.count_symbols(SymTagEnum);
    // Test program has Color enum
    EXPECT_GT(count, 0) << "Expected at least Color enum";
}

TEST_F(PdbSessionTest, EnumerateFunctions) {
    auto symbols = session_.enum_symbols(SymTagFunction);
    ASSERT_TRUE(symbols != nullptr);

    CComPtr<IDiaSymbol> symbol;
    ULONG fetched = 0;
    int count = 0;
    bool found_counter_get = false;

    while (SUCCEEDED(symbols->Next(1, &symbol, &fetched)) && fetched == 1) {
        pdbsql::SafeBSTR name;
        if (SUCCEEDED(symbol->get_name(name.ptr()))) {
            if (name.str().find("Counter::get") != std::string::npos) {
                found_counter_get = true;
            }
        }
        symbol.Release();
        count++;
    }

    EXPECT_GT(count, 0);
    EXPECT_TRUE(found_counter_get) << "Expected to find Counter::get function";
}

TEST_F(PdbSessionTest, EnumerateEnumValues) {
    auto enums = session_.enum_symbols(SymTagEnum);
    ASSERT_TRUE(enums != nullptr);

    CComPtr<IDiaSymbol> enum_sym;
    ULONG fetched = 0;
    bool found_color = false;

    while (SUCCEEDED(enums->Next(1, &enum_sym, &fetched)) && fetched == 1) {
        pdbsql::SafeBSTR name;
        if (SUCCEEDED(enum_sym->get_name(name.ptr()))) {
            if (name.str() == "Color") {
                found_color = true;

                // Check enum values
                CComPtr<IDiaEnumSymbols> values;
                if (SUCCEEDED(enum_sym->findChildren(SymTagData, nullptr, nsNone, &values)) && values) {
                    CComPtr<IDiaSymbol> val;
                    ULONG vfetched = 0;
                    int val_count = 0;

                    while (SUCCEEDED(values->Next(1, &val, &vfetched)) && vfetched == 1) {
                        val_count++;
                        val.Release();
                    }
                    EXPECT_EQ(val_count, 3) << "Expected COLOR_RED, COLOR_GREEN, COLOR_BLUE";
                }
            }
        }
        enum_sym.Release();
    }

    EXPECT_TRUE(found_color) << "Expected to find Color enum";
}
