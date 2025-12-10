cmake_minimum_required(VERSION 3.20)
project(pdbsql VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-only (MSDIA requires COM)
if(NOT WIN32)
    message(FATAL_ERROR "pdbsql requires Windows (MSDIA COM)")
endif()

# Output directories (only set if building standalone)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

# Find DIA SDK
set(DIA_SDK_PATHS
    "$ENV{VSINSTALLDIR}/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2022/Professional/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK"
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/DIA SDK"
)

foreach(path ${DIA_SDK_PATHS})
    if(EXISTS "${path}/include/dia2.h")
        set(DIA_SDK_DIR "${path}")
        break()
    endif()
endforeach()

if(NOT DIA_SDK_DIR)
    message(FATAL_ERROR "DIA SDK not found. Install Visual Studio with C++ tools.")
endif()

message(STATUS "Found DIA SDK: ${DIA_SDK_DIR}")

# DIA SDK include/lib
set(DIA_INCLUDE_DIR "${DIA_SDK_DIR}/include")
set(DIA_LIB_DIR "${DIA_SDK_DIR}/lib/amd64")

# ============================================================================
# libxsql dependency
# ============================================================================

if(TARGET xsql::xsql)
    # Part of monorepo - already available
    message(STATUS "pdbsql: Using xsql::xsql from parent project")
else()
    # Standalone build - add libxsql as subdirectory
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "pdbsql: Added libxsql from sibling directory")
    else()
        message(FATAL_ERROR "libxsql not found. Build as part of xsql monorepo or ensure ../libxsql exists.")
    endif()
endif()

# Main includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${DIA_INCLUDE_DIR})
link_directories(${DIA_LIB_DIR})

# CLI tool
add_subdirectory(src/cli)

# Test data (builds test_program.exe to generate PDB)
add_subdirectory(tests/testdata)

# Tests (optional)
option(PDBSQL_BUILD_TESTS "Build tests" ON)
if(PDBSQL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
