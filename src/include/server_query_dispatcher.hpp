#pragma once
// server_query_dispatcher.hpp - Single-threaded server execution with queuing

#include <condition_variable>
#include <future>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <sqlite3.h>
#include <xsql/database.hpp>
#include <xsql/socket/server.hpp>

#include "dia_helpers.hpp"  // For ComInit (COM init on worker thread)

namespace pdbsql {

// Runs all server queries on one COM-initialized worker thread with backpressure.
class ServerQueryDispatcher {
public:
    explicit ServerQueryDispatcher(xsql::Database& db)
        : db_(db), worker_(&ServerQueryDispatcher::worker_thread, this) {}

    ~ServerQueryDispatcher() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        cv_.notify_one();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    // Enqueue a query and block until it completes.
    xsql::socket::QueryResult run(const std::string& sql) {
        std::promise<xsql::socket::QueryResult> promise;
        auto future = promise.get_future();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push({sql, std::move(promise)});
        }
        cv_.notify_one();
        return future.get();
    }

private:
    struct Job {
        std::string sql;
        std::promise<xsql::socket::QueryResult> promise;
    };

    xsql::Database& db_;
    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<Job> queue_;
    bool stop_ = false;

    xsql::socket::QueryResult execute_sql(const std::string& sql) {
        xsql::socket::QueryResult result;

        struct Context {
            xsql::socket::QueryResult* result;
            bool first_row;
        } ctx{ &result, true };

        int rc = db_.exec(sql.c_str(),
            [](void* data, int argc, char** argv, char** col_names) -> int {
                auto* ctx = static_cast<Context*>(data);
                if (ctx->first_row) {
                    for (int i = 0; i < argc; i++) {
                        ctx->result->columns.push_back(col_names[i] ? col_names[i] : "");
                    }
                    ctx->first_row = false;
                }
                std::vector<std::string> row;
                row.reserve(static_cast<size_t>(argc));
                for (int i = 0; i < argc; i++) {
                    row.push_back(argv[i] ? argv[i] : "");
                }
                ctx->result->rows.push_back(std::move(row));
                return 0;
            },
            &ctx);

        if (rc != SQLITE_OK) {
            result.success = false;
            result.error = db_.last_error();
        } else {
            result.success = true;
        }

        return result;
    }

    void worker_thread() {
        // Ensure COM is initialized on the worker that touches DIA through xsql tables.
        ComInit com_init;
        while (true) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
                if (stop_ && queue_.empty()) {
                    break;
                }
                job = std::move(queue_.front());
                queue_.pop();
            }

            try {
                auto result = execute_sql(job.sql);
                job.promise.set_value(std::move(result));
            } catch (...) {
                try {
                    job.promise.set_exception(std::current_exception());
                } catch (...) {
                    // Swallow
                }
            }
        }
    }
};

} // namespace pdbsql
