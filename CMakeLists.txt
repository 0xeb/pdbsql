cmake_minimum_required(VERSION 3.20)
project(pdbsql VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-only (MSDIA requires COM)
if(NOT WIN32)
    message(FATAL_ERROR "pdbsql requires Windows (MSDIA COM)")
endif()

# AI Agent support (optional)
option(PDBSQL_WITH_AI_AGENT "Enable AI agent support via libagents" ON)

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
    # Part of monorepo - already available via add_subdirectory
    message(STATUS "pdbsql: Using xsql::xsql from parent project")
else()
    # Standalone build - try find_package first, then fallback to sibling directory
    find_package(xsql QUIET)
    if(xsql_FOUND)
        message(STATUS "pdbsql: Using xsql::xsql via find_package")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../libxsql/CMakeLists.txt")
        # Monorepo: sibling directory
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "pdbsql: Added libxsql from sibling directory")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/libxsql/CMakeLists.txt")
        # Standalone: submodule in external/
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/libxsql ${CMAKE_CURRENT_BINARY_DIR}/libxsql)
        message(STATUS "pdbsql: Added libxsql from external/libxsql submodule")
    else()
        message(FATAL_ERROR "libxsql not found. Either:\n"
            "  1. Build as part of xsql monorepo\n"
            "  2. Set xsql_DIR to the libxsql build directory\n"
            "  3. Install libxsql and ensure it's in CMAKE_PREFIX_PATH\n"
            "  4. Initialize submodule: git submodule update --init external/libxsql")
    endif()
endif()

# ============================================================================
# libagents dependency (AI agent support)
# ============================================================================

if(PDBSQL_WITH_AI_AGENT)
    if(TARGET libagents::libagents)
        # Part of monorepo - already available
        message(STATUS "pdbsql: Using libagents::libagents from parent project")
    else()
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/libagents/CMakeLists.txt")
            # Standalone: submodule in external/
            add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/libagents
                             ${CMAKE_CURRENT_BINARY_DIR}/libagents)
            message(STATUS "pdbsql: Added libagents from external/libagents submodule")
        else()
            message(FATAL_ERROR "libagents not found. Either:\n"
                "  1. Build as part of xsql monorepo\n"
                "  2. Initialize submodule: git submodule update --init external/libagents")
        endif()
    endif()

    # Embed the system prompt
    set(PROMPT_MD "${CMAKE_CURRENT_SOURCE_DIR}/prompts/pdbsql_agent.md")
    set(PROMPT_HPP "${CMAKE_CURRENT_SOURCE_DIR}/src/common/pdbsql_agent_prompt.hpp")
    add_custom_command(
        OUTPUT ${PROMPT_HPP}
        COMMAND ${CMAKE_COMMAND} -E env python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed_prompt.py"
                "${PROMPT_MD}" "${PROMPT_HPP}"
        DEPENDS ${PROMPT_MD}
        COMMENT "Embedding pdbsql_agent.md into pdbsql_agent_prompt.hpp"
        VERBATIM
    )
    add_custom_target(pdbsql_embed_prompt DEPENDS ${PROMPT_HPP})
endif()

# Main includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/common)
include_directories(${DIA_INCLUDE_DIR})
link_directories(${DIA_LIB_DIR})

# CLI tool
add_subdirectory(src/cli)

# Tests are in the private xsql monorepo (tests/pdbsql/)
