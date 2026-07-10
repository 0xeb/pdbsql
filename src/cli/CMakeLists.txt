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

# MCP server support
if(PDBSQL_WITH_MCP)
    target_link_libraries(pdbsql PRIVATE fastmcpp_core)
    target_compile_definitions(pdbsql PRIVATE PDBSQL_HAS_MCP)
    target_include_directories(pdbsql PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common)
    message(STATUS "pdbsql CLI: MCP server support enabled")
endif()

# HTTP server support
if(PDBSQL_WITH_HTTP)
    target_compile_definitions(pdbsql PRIVATE PDBSQL_HAS_HTTP)
    target_sources(pdbsql PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/http_server.cpp
    )
    target_include_directories(pdbsql PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common)
    message(STATUS "pdbsql CLI: HTTP server support enabled")
endif()
