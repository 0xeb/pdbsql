cmake_minimum_required(VERSION 3.20)
project(pdbsql VERSION 0.0.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-only (MSDIA requires COM)
if(NOT WIN32)
    message(FATAL_ERROR "pdbsql requires Windows (MSDIA COM)")
endif()

# AI Agent support (optional)
option(PDBSQL_WITH_AI_AGENT "Enable AI agent support via libagents" ON)
option(PDBSQL_WITH_HTTP "Build with HTTP REST server support" ON)

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
# libagents dependency (AI agent support)
# ============================================================================

if(PDBSQL_WITH_AI_AGENT)
    if(TARGET libagents::libagents)
        message(STATUS "pdbsql: Using libagents::libagents from parent project")
    else()
        message(STATUS "pdbsql: Fetching libagents from GitHub...")
        set(LIBAGENTS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(LIBAGENTS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(LIBAGENTS_BUILD_CLI OFF CACHE BOOL "" FORCE)
        include(FetchContent)
        FetchContent_Declare(libagents
            GIT_REPOSITORY https://github.com/0xeb/libagents.git
            GIT_TAG        main
            GIT_SHALLOW    TRUE
        )
        FetchContent_MakeAvailable(libagents)
    endif()

    # Embed the system prompt
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(PROMPT_MD "${CMAKE_CURRENT_SOURCE_DIR}/prompts/pdbsql_agent.md")
    set(PROMPT_HPP "${CMAKE_CURRENT_SOURCE_DIR}/src/common/pdbsql_agent_prompt.hpp")
    add_custom_command(
        OUTPUT ${PROMPT_HPP}
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/scripts/embed_prompt.py"
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

# Additional integration tests may be provided by parent projects.
