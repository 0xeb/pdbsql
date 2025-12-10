# pdbsql CLI tool

add_executable(pdbsql main.cpp)

target_link_libraries(pdbsql PRIVATE
    sqlite3
    diaguids
)

# Windows libraries for COM
target_link_libraries(pdbsql PRIVATE
    ole32
    oleaut32
)
