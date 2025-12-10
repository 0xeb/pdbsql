# tests/CMakeLists.txt - GTest test suite for pdbsql

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test executable
add_executable(pdbsql_tests
    test_pdb_session.cpp
    test_pdb_tables.cpp
)

target_include_directories(pdbsql_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/include
    ${DIA_INCLUDE_DIR}
)

target_link_libraries(pdbsql_tests PRIVATE
    GTest::gtest_main
    xsql::xsql
    diaguids
)

target_link_directories(pdbsql_tests PRIVATE ${DIA_LIB_DIR})

# Define path to test PDB (use CMAKE_CURRENT_SOURCE_DIR for monorepo compatibility)
target_compile_definitions(pdbsql_tests PRIVATE
    TEST_PDB_PATH="${CMAKE_CURRENT_SOURCE_DIR}/testdata/test_program.pdb"
)

include(GoogleTest)
gtest_discover_tests(pdbsql_tests)
