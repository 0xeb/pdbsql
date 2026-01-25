// test_pdb_tables.cpp - Tests for virtual tables

#include <gtest/gtest.h>
#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include <xsql/database.hpp>
#include <sqlite3.h>
#include <string>
#include <vector>

class PdbTablesTest : public ::testing::Test {
protected:
    pdbsql::ComInit com_init_;
    pdbsql::PdbSession session_;
    std::unique_ptr<xsql::Database> db_;
    std::unique_ptr<pdbsql::TableRegistry> registry_;

    void SetUp() override {
        ASSERT_TRUE(com_init_.ok()) << "COM initialization failed";
        ASSERT_TRUE(session_.open(TEST_PDB_PATH)) << session_.last_error();

        db_ = std::make_unique<xsql::Database>();
        ASSERT_TRUE(db_->is_open()) << "Failed to open in-memory SQLite database";

        registry_ = std::make_unique<pdbsql::TableRegistry>(session_);
        registry_->register_all(*db_);
    }

    void TearDown() override {
        registry_.reset();
        db_.reset();
    }

    // Helper to execute query and count rows
    int count_rows(const char* sql) {
        int count = 0;
        char* err = nullptr;
        db_->exec(sql, [](void* data, int, char**, char**) -> int {
            (*static_cast<int*>(data))++;
            return 0;
        }, &count);

        return count;
    }

    // Helper to get single integer value
    int64_t get_int(const char* sql) {
        int64_t result = 0;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_->handle(), sql, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                result = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
        return result;
    }

    // Helper to get single string value
    std::string get_text(const char* sql) {
        std::string result;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_->handle(), sql, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (text) result = text;
            }
            sqlite3_finalize(stmt);
        }
        return result;
    }

    std::string get_query_plan_detail(const char* sql) {
        std::string result;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_->handle(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            if (stmt) sqlite3_finalize(stmt);
            return result;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            if (!text) continue;
            if (!result.empty()) result += "\n";
            result += text;
        }

        sqlite3_finalize(stmt);
        return result;
    }
};

// ============================================================================
// Basic Table Tests
// ============================================================================

TEST_F(PdbTablesTest, AllTablesExist) {
    std::vector<std::string> expected_tables = {
        "functions", "publics", "data", "udts", "enums", "typedefs",
        "thunks", "labels", "compilands", "source_files", "line_numbers",
        "sections", "udt_members", "enum_values", "base_classes",
        "locals", "parameters"
    };

    for (const auto& table : expected_tables) {
        std::string sql = "SELECT COUNT(*) FROM " + table;
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_->handle(), sql.c_str(), -1, &stmt, nullptr);
        EXPECT_EQ(rc, SQLITE_OK) << "Table '" << table << "' should exist";
        if (stmt) sqlite3_finalize(stmt);
    }
}

// ============================================================================
// Functions Table Tests
// ============================================================================

TEST_F(PdbTablesTest, FunctionsTableHasRows) {
    int count = count_rows("SELECT * FROM functions");
    EXPECT_GT(count, 10) << "Expected functions in PDB";
}

TEST_F(PdbTablesTest, FunctionsTableFindCounterGet) {
    int count = count_rows("SELECT * FROM functions WHERE name LIKE '%Counter::get%'");
    EXPECT_EQ(count, 1) << "Expected exactly one Counter::get function";
}

TEST_F(PdbTablesTest, FunctionsTableFindMain) {
    int count = count_rows("SELECT * FROM functions WHERE name = 'main'");
    EXPECT_EQ(count, 1) << "Expected main function";
}

TEST_F(PdbTablesTest, FunctionsHaveRVA) {
    int count = count_rows("SELECT * FROM functions WHERE rva > 0");
    EXPECT_GT(count, 0) << "Expected functions with RVA values";
}

// ============================================================================
// UDTs Table Tests
// ============================================================================

TEST_F(PdbTablesTest, UdtsTableFindCounter) {
    int count = count_rows("SELECT * FROM udts WHERE name = 'Counter'");
    EXPECT_GE(count, 1) << "Expected Counter class";
}

TEST_F(PdbTablesTest, UdtsTableFindRectangle) {
    int count = count_rows("SELECT * FROM udts WHERE name = 'Rectangle'");
    EXPECT_GE(count, 1) << "Expected Rectangle struct";
}

// ============================================================================
// Enums Table Tests
// ============================================================================

TEST_F(PdbTablesTest, EnumsTableFindColor) {
    int count = count_rows("SELECT * FROM enums WHERE name = 'Color'");
    EXPECT_GE(count, 1) << "Expected Color enum";
}

// ============================================================================
// Enum Values Table Tests
// ============================================================================

TEST_F(PdbTablesTest, EnumValuesForColor) {
    int count = count_rows("SELECT * FROM enum_values WHERE enum_name = 'Color'");
    EXPECT_EQ(count, 3) << "Expected COLOR_RED, COLOR_GREEN, COLOR_BLUE";
}

TEST_F(PdbTablesTest, EnumValuesHaveCorrectValues) {
    int64_t red = get_int("SELECT value FROM enum_values WHERE name = 'COLOR_RED'");
    int64_t green = get_int("SELECT value FROM enum_values WHERE name = 'COLOR_GREEN'");
    int64_t blue = get_int("SELECT value FROM enum_values WHERE name = 'COLOR_BLUE'");

    EXPECT_EQ(red, 0);
    EXPECT_EQ(green, 1);
    EXPECT_EQ(blue, 2);
}

// ============================================================================
// UDT Members Table Tests
// ============================================================================

TEST_F(PdbTablesTest, UdtMembersForCounter) {
    int count = count_rows("SELECT * FROM udt_members WHERE udt_name = 'Counter'");
    EXPECT_GE(count, 1) << "Expected m_value member in Counter";
}

TEST_F(PdbTablesTest, UdtMembersHaveName) {
    std::string name = get_text("SELECT name FROM udt_members WHERE udt_name = 'Counter' LIMIT 1");
    EXPECT_EQ(name, "m_value");
}

// ============================================================================
// Base Classes Table Tests
// ============================================================================

TEST_F(PdbTablesTest, BaseClassesExist) {
    // std::exception hierarchy should be present from CRT
    int count = count_rows("SELECT * FROM base_classes WHERE base_name = 'std::exception'");
    EXPECT_GT(count, 0) << "Expected classes derived from std::exception";
}

// ============================================================================
// Compilands Table Tests
// ============================================================================

TEST_F(PdbTablesTest, CompilandsTableHasRows) {
    int count = count_rows("SELECT * FROM compilands");
    EXPECT_GT(count, 0) << "Expected compilands in PDB";
}

TEST_F(PdbTablesTest, CompilandsContainTestProgram) {
    int count = count_rows("SELECT * FROM compilands WHERE name LIKE '%test_program%'");
    EXPECT_GE(count, 1) << "Expected test_program.obj compiland";
}

// ============================================================================
// Source Files Table Tests
// ============================================================================

TEST_F(PdbTablesTest, SourceFilesTableHasRows) {
    int count = count_rows("SELECT * FROM source_files");
    EXPECT_GT(count, 0) << "Expected source files in PDB";
}

TEST_F(PdbTablesTest, SourceFilesContainTestProgram) {
    int count = count_rows("SELECT * FROM source_files WHERE filename LIKE '%test_program.cpp%'");
    EXPECT_EQ(count, 1) << "Expected test_program.cpp source file";
}

// ============================================================================
// Public Symbols Table Tests
// ============================================================================

TEST_F(PdbTablesTest, PublicsTableHasRows) {
    int count = count_rows("SELECT * FROM publics");
    EXPECT_GT(count, 0) << "Expected public symbols in PDB";
}

// ============================================================================
// Data Table Tests
// ============================================================================

TEST_F(PdbTablesTest, DataTableHasRows) {
    int count = count_rows("SELECT * FROM data");
    EXPECT_GT(count, 0) << "Expected data symbols in PDB";
}

// ============================================================================
// SQL Query Tests
// ============================================================================

TEST_F(PdbTablesTest, JoinQuery) {
    // Test joining enum_values with enums
    int count = count_rows(
        "SELECT ev.name, ev.value "
        "FROM enum_values ev "
        "INNER JOIN enums e ON ev.enum_id = e.id "
        "WHERE e.name = 'Color'"
    );
    EXPECT_EQ(count, 3) << "Expected 3 Color enum values via join";
}

TEST_F(PdbTablesTest, AggregateQuery) {
    int64_t count = get_int("SELECT COUNT(DISTINCT udt_name) FROM udt_members");
    EXPECT_GT(count, 0) << "Expected distinct UDTs with members";
}

TEST_F(PdbTablesTest, OrderByQuery) {
    // Should not fail with ORDER BY
    int count = count_rows("SELECT * FROM functions ORDER BY rva LIMIT 5");
    EXPECT_LE(count, 5);
}

TEST_F(PdbTablesTest, LikeQuery) {
    int count = count_rows("SELECT * FROM functions WHERE name LIKE 'Counter::%'");
    EXPECT_GE(count, 3) << "Expected Counter::get, Counter::increment, Counter::add, Counter::Counter";
}

// ============================================================================
// Query Plan / Constraint Pushdown Tests
// ============================================================================

TEST_F(PdbTablesTest, QueryPlanUsesNameEqFilter) {
    std::string detail = get_query_plan_detail(
        "EXPLAIN QUERY PLAN SELECT * FROM functions WHERE name = 'main'"
    );
    EXPECT_NE(detail.find("VIRTUAL TABLE INDEX"), std::string::npos);
    EXPECT_EQ(detail.find("VIRTUAL TABLE INDEX 0"), std::string::npos);
}

TEST_F(PdbTablesTest, QueryPlanUsesIdEqFilter) {
    int64_t id = get_int("SELECT id FROM functions WHERE name = 'main'");
    ASSERT_GT(id, 0);

    std::string sql = "EXPLAIN QUERY PLAN SELECT * FROM functions WHERE id = " + std::to_string(id);
    std::string detail = get_query_plan_detail(sql.c_str());
    EXPECT_NE(detail.find("VIRTUAL TABLE INDEX"), std::string::npos);
    EXPECT_EQ(detail.find("VIRTUAL TABLE INDEX 0"), std::string::npos);
}

TEST_F(PdbTablesTest, QueryPlanUsesEnumNameEqFilter) {
    std::string detail = get_query_plan_detail(
        "EXPLAIN QUERY PLAN SELECT * FROM enum_values WHERE enum_name = 'Color'"
    );
    EXPECT_NE(detail.find("VIRTUAL TABLE INDEX"), std::string::npos);
    EXPECT_EQ(detail.find("VIRTUAL TABLE INDEX 0"), std::string::npos);
}

TEST_F(PdbTablesTest, QueryPlanLikeStaysFullScan) {
    std::string detail = get_query_plan_detail(
        "EXPLAIN QUERY PLAN SELECT * FROM functions WHERE name LIKE 'Counter::%'"
    );
    EXPECT_NE(detail.find("VIRTUAL TABLE INDEX 0"), std::string::npos);
}
