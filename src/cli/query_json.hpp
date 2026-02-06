#pragma once

#include <xsql/database.hpp>
#include <string>
#include <sstream>
#include <cstdio>

inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 10);
    for (char ch : s) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(ch));
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
    return out;
}

inline std::string query_result_to_json(xsql::Database& db, const std::string& sql) {
    auto result = db.query(sql);
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (result.ok() ? "true" : "false");

    if (result.ok()) {
        json << ",\"columns\":[";
        for (size_t i = 0; i < result.columns.size(); i++) {
            if (i > 0) json << ",";
            json << "\"" << json_escape(result.columns[i]) << "\"";
        }
        json << "]";

        json << ",\"rows\":[";
        for (size_t i = 0; i < result.rows.size(); i++) {
            if (i > 0) json << ",";
            json << "[";
            for (size_t c = 0; c < result.rows[i].size(); c++) {
                if (c > 0) json << ",";
                json << "\"" << json_escape(result.rows[i][c]) << "\"";
            }
            json << "]";
        }
        json << "]";
        json << ",\"row_count\":" << result.rows.size();
    } else {
        json << ",\"error\":\"" << json_escape(result.error) << "\"";
    }

    json << "}";
    return json.str();
}
