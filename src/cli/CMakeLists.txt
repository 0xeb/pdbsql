# pdbsql CLI tool

add_executable(pdbsql main.cpp)

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
