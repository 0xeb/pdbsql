# pdbsql CLI tool

set(PDBSQL_SOURCES
    main.cpp
    remote_mode.cpp
)

# AI agent support
if(PDBSQL_WITH_AI_AGENT)
    list(APPEND PDBSQL_SOURCES
        ../common/ai_agent.cpp
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

if(PDBSQL_WITH_AI_AGENT)
    add_dependencies(pdbsql pdbsql_embed_prompt)
endif()

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

# AI agent dependencies
if(PDBSQL_WITH_AI_AGENT)
    target_link_libraries(pdbsql PRIVATE libagents::libagents fastmcpp_core)
    target_compile_definitions(pdbsql PRIVATE PDBSQL_HAS_AI_AGENT)
    target_include_directories(pdbsql PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
        ${CMAKE_CURRENT_SOURCE_DIR}/../../external/libagents/external/fastmcpp/include
    )
    message(STATUS "pdbsql CLI: AI agent support enabled")
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
