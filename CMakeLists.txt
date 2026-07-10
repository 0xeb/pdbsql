#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#

cmake_minimum_required(VERSION 3.20)
project(pdbsql VERSION 0.0.4 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows VERSIONINFO wiring (version is from project() above)
set(TOOL_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(TOOL_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(TOOL_VERSION_PATCH ${PROJECT_VERSION_PATCH})
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/versioninfo.cmake)

# Windows-only (MSDIA requires COM)
if(NOT WIN32)
    message(FATAL_ERROR "pdbsql requires Windows (MSDIA COM)")
endif()

option(PDBSQL_WITH_HTTP "Build with HTTP REST server support" ON)
option(PDBSQL_WITH_MCP "Build with MCP server support (fastmcpp)" ON)

# HTTP support requires thinclient from libxsql
if(PDBSQL_WITH_HTTP)
    message(STATUS "pdbsql: Building with HTTP server support")
    set(XSQL_WITH_THINCLIENT ON CACHE BOOL "" FORCE)
endif()

# Output directories (only set if building standalone)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

# Find DIA SDK. The DIA SDK lives at "<VS install root>/DIA SDK". Search the
# environment-provided install dir first, then glob every Visual Studio install
# regardless of version/edition — VS 2019/2022 use the year in the path
# (".../2022/Enterprise"), while VS 2026+ use the major version (".../18/Enterprise").
set(DIA_SDK_PATHS
    "$ENV{VSINSTALLDIR}/DIA SDK"
    "$ENV{VCINSTALLDIR}/../DIA SDK"
)
file(GLOB _vs_dia_candidates
    "C:/Program Files/Microsoft Visual Studio/*/*/DIA SDK"
    "C:/Program Files (x86)/Microsoft Visual Studio/*/*/DIA SDK"
)
list(APPEND DIA_SDK_PATHS ${_vs_dia_candidates})

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
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DIA_LIB_DIR "${DIA_SDK_DIR}/lib/amd64")
else()
    set(DIA_LIB_DIR "${DIA_SDK_DIR}/lib")
endif()

# ============================================================================
# libxsql dependency
# ============================================================================
find_package(Threads REQUIRED)

if(TARGET xsql::xsql)
    message(STATUS "pdbsql: Using xsql::xsql from parent project")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
    message(STATUS "pdbsql: Added libxsql from sibling directory")
else()
    message(STATUS "pdbsql: Fetching libxsql from GitHub...")
    include(FetchContent)
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        main
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(libxsql)
endif()

# ============================================================================
# MCP support (optional, uses fastmcpp)
# ============================================================================

if(PDBSQL_WITH_MCP)
    message(STATUS "pdbsql: Building with MCP support via fastmcpp")
    if(NOT TARGET fastmcpp_core)
        set(FASTMCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_POST_STREAMING OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_SAMPLING_HTTP_HANDLERS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_FETCH_CURL OFF CACHE BOOL "" FORCE)
        message(STATUS "pdbsql: Fetching fastmcpp from GitHub...")
        include(FetchContent)
        FetchContent_Declare(fastmcpp
            GIT_REPOSITORY https://github.com/0xeb/fastmcpp.git
            GIT_TAG        main
            GIT_SHALLOW    TRUE
        )
        FetchContent_MakeAvailable(fastmcpp)
    endif()
    if(MSVC AND TARGET fastmcpp_core)
        target_compile_options(fastmcpp_core PRIVATE /MP)
    endif()
endif()

# Main includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/common)
include_directories(${DIA_INCLUDE_DIR})
link_directories(${DIA_LIB_DIR})

# CLI tool
add_subdirectory(src/cli)

# Additional integration tests may be provided by parent projects.
