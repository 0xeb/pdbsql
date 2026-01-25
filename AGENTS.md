# Repository Guidelines

## Project Structure & Module Organization
- `src/cli/`: entrypoint for the `pdbsql` CLI (optionally links AI agent support).
- `src/common/`: shared helpers, command handlers, and optional AI prompt embedding.
- `src/include/`: public headers for PDB parsing and DIA helpers.
- `tests/`: GoogleTest suites plus `tests/testdata/` which builds `test_program.pdb`.
- `external/`: git submodules (e.g., `libxsql`; optionally `libagents`).
- `build/`: out-of-source build artifacts; `prompts/` holds the agent prompt; `scripts/embed_prompt.py` generates `pdbsql_agent_prompt.hpp` when AI support is on.

## Build, Test, and Development Commands
- Initialize deps: `git submodule update --init --recursive`.
- Configure (Release by default): `cmake -B build [-DPDBSQL_WITH_AI_AGENT=ON]`.
- Build: `cmake --build build --config Release`.
- Run tests: `ctest --test-dir build -C Release --output-on-failure`.
- Local debug run: `build\\bin\\Release\\pdbsql.exe <PDB path>`.
- Prereqs: Windows + Visual Studio DIA SDK; ensure `DIA SDK/include` and `DIA SDK/lib/amd64` are discoverable.

## Coding Style & Naming Conventions
- C++17, 4-space indent, headers use `#pragma once`; include local headers before system headers.
- Class/struct names use `PascalCase` (e.g., `PdbSession`); methods/functions are lower_snake_case; member fields keep trailing underscore; constants use `kPrefix`.
- Favor RAII and `CComPtr` for DIA handles; return early on failures and populate `last_error()`-style strings.
- Keep commands in `pdbsql_commands.hpp` self-contained and side-effect aware; prefer small helpers in `src/common/`.

## Testing Guidelines
- Framework: GoogleTest (fetched in `tests/CMakeLists.txt`).
- File naming: `test_*.cpp`; test cases follow `TEST(Suite, Case)` or fixtures for shared setup.
- Test data: rely on `tests/testdata/test_program.pdb` generated during the build; avoid hardcoding absolute paths.
- Run `ctest` after any change to DIA interactions, CLI commands, or prompt embedding logic.

## Commit & Pull Request Guidelines
- Use Conventional Commit prefixes (`feat:`, `chore:`, `refactor:`, `tests:`) mirroring recent history.
- Commits should be focused and buildable; include updates to tests when behavior changes.
- PRs: describe intent and scope, note dependency/submodule updates, attach test output (`ctest ... --output-on-failure`), and include screenshots only when UI/console behavior is relevant.

## Configuration & Security Notes
- Builds assume Windows; fail fast if DIA SDK is missing. Keep `-DPDBSQL_WITH_AI_AGENT=ON` off unless `external/libagents` is present.
- Avoid committing generated files under `build/` or embedded prompt outputs; regenerate via CMake when needed.
