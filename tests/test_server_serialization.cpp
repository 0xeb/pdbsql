// test_server_serialization.cpp - Ensure server query execution is serialized

#include <gtest/gtest.h>
#include <future>
#include <vector>

#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include "server_query_dispatcher.hpp"
#include <xsql/database.hpp>

class ServerSerializationTest : public ::testing::Test {
protected:
    pdbsql::ComInit com_init_;
    pdbsql::PdbSession session_;
    std::unique_ptr<xsql::Database> db_;
    std::unique_ptr<pdbsql::TableRegistry> registry_;
    std::unique_ptr<pdbsql::ServerQueryDispatcher> dispatcher_;

    void SetUp() override {
        ASSERT_TRUE(com_init_.ok()) << "COM initialization failed";
        ASSERT_TRUE(session_.open(TEST_PDB_PATH)) << session_.last_error();

        db_ = std::make_unique<xsql::Database>();
        ASSERT_TRUE(db_->is_open()) << "Failed to open in-memory SQLite database";

        registry_ = std::make_unique<pdbsql::TableRegistry>(session_);
        registry_->register_all(*db_);

        dispatcher_ = std::make_unique<pdbsql::ServerQueryDispatcher>(*db_);
    }

    void TearDown() override {
        dispatcher_.reset();
        registry_.reset();
        db_.reset();
    }
};

TEST_F(ServerSerializationTest, RunsQueryAndReturnsRows) {
    auto result = dispatcher_->run("SELECT name FROM functions WHERE name LIKE '%main%'");
    ASSERT_TRUE(result.success);
    ASSERT_FALSE(result.columns.empty());
    ASSERT_FALSE(result.rows.empty());
}

TEST_F(ServerSerializationTest, HandlesConcurrentQueriesSerialized) {
    auto worker = [this](const std::string& sql) {
        return dispatcher_->run(sql);
    };

    std::vector<std::future<xsql::socket::QueryResult>> futures;
    futures.emplace_back(std::async(std::launch::async, worker, "SELECT COUNT(*) FROM functions"));
    futures.emplace_back(std::async(std::launch::async, worker, "SELECT COUNT(*) FROM enums"));
    futures.emplace_back(std::async(std::launch::async, worker, "SELECT COUNT(*) FROM udts"));

    for (auto& f : futures) {
        auto result = f.get();
        EXPECT_TRUE(result.success);
        EXPECT_EQ(result.rows.size(), 1u);
    }
}

TEST_F(ServerSerializationTest, ReportsErrorsFromBadSql) {
    auto result = dispatcher_->run("SELECT * FROM not_a_table");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}
