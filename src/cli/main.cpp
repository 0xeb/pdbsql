// pdbsql CLI - SQL interface to PDB files
// Usage: pdbsql <pdb_file> [query]
//        pdbsql <pdb_file> -i   (interactive mode)

#include "pdb_session.hpp"
#include "pdb_tables.hpp"
#include <sqlite3.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <iostream>

void print_usage(const char* prog) {
    printf("pdbsql - SQL interface to PDB files\n\n");
    printf("Usage:\n");
    printf("  %s <pdb_file>                  Dump symbol counts\n", prog);
    printf("  %s <pdb_file> \"<query>\"        Execute SQL query\n", prog);
    printf("  %s <pdb_file> -i               Interactive mode\n", prog);
    printf("\nCore Symbol Tables:\n");
    printf("  functions     - Function symbols (id, name, undecorated, rva, length, section, offset)\n");
    printf("  publics       - Public symbols (exports)\n");
    printf("  data          - Global/static data symbols\n");
    printf("  udts          - User-defined types (structs, classes, unions)\n");
    printf("  enums         - Enumerations\n");
    printf("  typedefs      - Type aliases\n");
    printf("  thunks        - Thunk symbols (import stubs)\n");
    printf("  labels        - Code labels\n");
    printf("\nCompilation Unit Tables:\n");
    printf("  compilands    - Object files / compilation units\n");
    printf("  source_files  - Source file paths\n");
    printf("  line_numbers  - Source line to RVA mapping\n");
    printf("\nStructure Tables:\n");
    printf("  sections      - PE sections (from section contributions)\n");
    printf("\nType Hierarchy Tables:\n");
    printf("  udt_members   - UDT member fields (struct/class members)\n");
    printf("  enum_values   - Enum value constants\n");
    printf("  base_classes  - Base class relationships\n");
    printf("\nFunction Detail Tables:\n");
    printf("  locals        - Local variables (per function)\n");
    printf("  parameters    - Function parameters (per function)\n");
    printf("\nExamples:\n");
    printf("  %s test.pdb \"SELECT name, rva FROM functions LIMIT 10\"\n", prog);
    printf("  %s test.pdb \"SELECT * FROM functions WHERE name LIKE '%%main%%'\"\n", prog);
    printf("  %s test.pdb \"SELECT COUNT(*) FROM publics\"\n", prog);
    printf("  %s test.pdb \"SELECT * FROM udt_members WHERE udt_name='Counter'\"\n", prog);
    printf("  %s test.pdb \"SELECT * FROM enum_values WHERE enum_name='Color'\"\n", prog);
}

// SQLite callback for printing results
int query_callback(void* data, int argc, char** argv, char** col_names) {
    static bool header_printed = false;
    int* row_count = static_cast<int*>(data);

    // Print header on first row
    if (*row_count == 0) {
        for (int i = 0; i < argc; i++) {
            if (i > 0) printf("\t");
            printf("%s", col_names[i]);
        }
        printf("\n");
        for (int i = 0; i < argc; i++) {
            if (i > 0) printf("\t");
            printf("--------");
        }
        printf("\n");
    }

    // Print row
    for (int i = 0; i < argc; i++) {
        if (i > 0) printf("\t");
        printf("%s", argv[i] ? argv[i] : "NULL");
    }
    printf("\n");

    (*row_count)++;
    return 0;
}

bool execute_query(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int row_count = 0;

    int rc = sqlite3_exec(db, sql, query_callback, &row_count, &err);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err ? err : "unknown");
        if (err) sqlite3_free(err);
        return false;
    }

    printf("\n(%d rows)\n", row_count);
    return true;
}

void interactive_mode(sqlite3* db) {
    printf("pdbsql interactive mode. Type .quit to exit.\n\n");

    std::string line;
    while (true) {
        printf("pdbsql> ");
        std::getline(std::cin, line);

        if (line.empty()) continue;
        if (line == ".quit" || line == ".exit" || line == "quit" || line == "exit") break;

        if (line == ".tables") {
            execute_query(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
            continue;
        }

        if (line == ".schema") {
            execute_query(db, "SELECT sql FROM sqlite_master WHERE type='table'");
            continue;
        }

        if (line[0] == '.') {
            printf("Unknown command: %s\n", line.c_str());
            printf("Commands: .tables, .schema, .quit\n");
            continue;
        }

        execute_query(db, line.c_str());
    }
}

void dump_symbol_counts(pdbsql::PdbSession& session) {
    printf("Symbol Counts:\n");
    printf("  Functions:      %ld\n", session.count_symbols(SymTagFunction));
    printf("  Public Symbols: %ld\n", session.count_symbols(SymTagPublicSymbol));
    printf("  Data:           %ld\n", session.count_symbols(SymTagData));
    printf("  UDTs:           %ld\n", session.count_symbols(SymTagUDT));
    printf("  Enums:          %ld\n", session.count_symbols(SymTagEnum));
    printf("  Typedefs:       %ld\n", session.count_symbols(SymTagTypedef));
    printf("  Compilands:     %ld\n", session.count_symbols(SymTagCompiland));
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* pdb_path = argv[1];

    // Open PDB
    pdbsql::PdbSession session;
    if (!session.open(pdb_path)) {
        fprintf(stderr, "Error: %s\n", session.last_error().c_str());
        return 1;
    }

    printf("pdbsql - Loaded: %s\n\n", pdb_path);

    // Open SQLite in-memory database
    sqlite3* db = nullptr;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to open SQLite database\n");
        return 1;
    }

    // Register virtual tables
    pdbsql::TableRegistry registry(session);
    registry.register_all(db);

    // Determine mode
    if (argc == 2) {
        // No query - dump counts
        dump_symbol_counts(session);
    }
    else if (argc == 3 && (strcmp(argv[2], "-i") == 0 || strcmp(argv[2], "--interactive") == 0)) {
        // Interactive mode
        interactive_mode(db);
    }
    else {
        // Execute query from command line
        execute_query(db, argv[2]);
    }

    sqlite3_close(db);
    return 0;
}
