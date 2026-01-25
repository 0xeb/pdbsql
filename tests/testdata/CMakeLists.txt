# Test program for PDB generation
# Builds test_program.exe which generates test_program.pdb

add_executable(test_program test_program.cpp)

# Generate PDB with debug info
target_compile_options(test_program PRIVATE /Zi)
target_link_options(test_program PRIVATE /DEBUG)

# Copy PDB to predictable location after build
add_custom_command(TARGET test_program POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_PDB_FILE:test_program>"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_program.pdb"
    COMMENT "Copying test_program.pdb to testdata directory"
)
