# pdbsql CLI tool

set(PDBSQL_SOURCES
    main.cpp
)

# MCP server support
if(PDBSQL_WITH_MCP)
    list(APPEND PDBSQL_SOURCES
        ../common/mcp_server.cpp
        mcp_mode.cpp
    )
endif()

# HTTP mode source
if(PDBSQL_WITH_HTTP)
    list(APPEND PDBSQL_SOURCES
        http_mode.cpp
    )
endif()

add_executable(pdbsql ${PDBSQL_SOURCES})

# Windows VS_VERSION_INFO resource
xsql_add_versioninfo(pdbsql
    FILETYPE          VFT_APP
    DESCRIPTION       "pdbsql command-line interface for PDB files"
    ORIGINAL_FILENAME "pdbsql.exe")

target_link_libraries(pdbsql PRIVATE
    xsql::xsql
    diaguids
)

# Windows libraries for COM and sockets
target_link_libraries(pdbsql PRIVATE
    ole32
    oleaut32
    ws2_32
)

# The embedded agent reference (pdbsql_agent_prompt / _gen) is defined in the
# top-level pdbsql/CMakeLists.txt whenever HTTP or MCP is on -- both server
# modes serve it (GET /help and the pdbsql_help MCP tool).
if(PDBSQL_WITH_HTTP OR PDBSQL_WITH_MCP)
    target_link_libraries(pdbsql PRIVATE pdbsql_agent_prompt)
    add_dependencies(pdbsql pdbsql_agent_prompt_gen)
endif()

# MCP server support
if(PDBSQL_WITH_MCP)
    target_link_libraries(pdbsql PRIVATE fastmcpp_core)
    # PDBSQL_VERSION_STRING is what the MCP handler reports to a connecting
    # agent. Derived from project(pdbsql VERSION ...) so it cannot drift from
    # the single source of truth scripts/check-version.py enforces.
    target_compile_definitions(pdbsql PRIVATE
        PDBSQL_HAS_MCP
        PDBSQL_VERSION_STRING="${PROJECT_VERSION}")
    target_include_directories(pdbsql PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common)
    message(STATUS "pdbsql CLI: MCP server support enabled")
endif()

# HTTP server support
if(PDBSQL_WITH_HTTP)
    target_compile_definitions(pdbsql PRIVATE PDBSQL_HAS_HTTP)
    target_sources(pdbsql PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/http_server.cpp
    )
    target_include_directories(pdbsql PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
    message(STATUS "pdbsql CLI: HTTP server support enabled")
endif()
