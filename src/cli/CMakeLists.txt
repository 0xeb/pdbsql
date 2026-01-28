# pdbsql CLI tool

set(PDBSQL_SOURCES main.cpp)

# AI agent support
if(PDBSQL_WITH_AI_AGENT)
    list(APPEND PDBSQL_SOURCES
        ../common/ai_agent.cpp
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
    target_link_libraries(pdbsql PRIVATE libagents::libagents)
    target_compile_definitions(pdbsql PRIVATE PDBSQL_HAS_AI_AGENT)
    message(STATUS "pdbsql CLI: AI agent support enabled")
endif()

# HTTP server support
if(PDBSQL_WITH_HTTP)
    target_compile_definitions(pdbsql PRIVATE PDBSQL_HAS_HTTP)
    message(STATUS "pdbsql CLI: HTTP server support enabled")
endif()
