#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

struct TablePrinter {
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
    std::vector<size_t> widths;

    void set_columns(const std::vector<std::string>& cols) {
        columns = cols;
        widths.resize(cols.size(), 0);
        for (size_t i = 0; i < cols.size(); i++) {
            widths[i] = (std::max)(widths[i], cols[i].length());
        }
    }

    void add_row(const std::vector<std::string>& row) {
        for (size_t i = 0; i < row.size() && i < widths.size(); i++) {
            widths[i] = (std::max)(widths[i], row[i].length());
        }
        rows.push_back(row);
    }

    void add_row(int argc, char** argv, char** colNames) {
        if (columns.empty()) {
            columns.reserve(argc);
            widths.resize(argc, 0);
            for (int i = 0; i < argc; i++) {
                columns.push_back(colNames[i] ? colNames[i] : "");
                widths[i] = (std::max)(widths[i], columns[i].length());
            }
        }

        std::vector<std::string> row;
        row.reserve(argc);
        for (int i = 0; i < argc; i++) {
            std::string val = argv[i] ? argv[i] : "NULL";
            row.push_back(val);
            widths[i] = (std::max)(widths[i], val.length());
        }
        rows.push_back(std::move(row));
    }

    void print() {
        if (columns.empty()) return;

        // Header separator
        std::string sep = "+";
        for (size_t w : widths) {
            sep += std::string(w + 2, '-') + "+";
        }

        // Header
        std::cout << sep << "\n| ";
        for (size_t i = 0; i < columns.size(); i++) {
            std::cout << std::left;
            std::cout.width(widths[i]);
            std::cout << columns[i] << " | ";
        }
        std::cout << "\n" << sep << "\n";

        // Rows
        for (const auto& row : rows) {
            std::cout << "| ";
            for (size_t i = 0; i < row.size(); i++) {
                std::cout << std::left;
                std::cout.width(widths[i]);
                std::cout << row[i] << " | ";
            }
            std::cout << "\n";
        }
        std::cout << sep << "\n";
        std::cout << rows.size() << " row(s)\n";
    }
};
