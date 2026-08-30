#!/usr/bin/env python3
"""
Converts prompts/pdbsql_agent.md to a C++ header with an embedded raw string
literal (pdbsql::AGENT_PROMPT_TEXT), served over HTTP from GET /help.
Only regenerates if the output header is older than the source markdown.

Run: python scripts/embed_prompt.py prompts/pdbsql_agent.md <output.hpp>
"""

import sys
import os
from datetime import datetime


def needs_regeneration(input_path: str, output_path: str) -> bool:
    """Check if output needs regeneration based on file timestamps."""
    if not os.path.exists(output_path):
        return True
    input_mtime = os.path.getmtime(input_path)
    output_mtime = os.path.getmtime(output_path)
    return input_mtime > output_mtime


def split_content(content: str, max_chunk: int = 15000) -> list:
    """Split content into chunks that MSVC can handle.

    MSVC has a ~16KB limit per string literal segment.
    We split at line boundaries to keep it readable.
    """
    chunks = []
    lines = content.split('\n')
    current_chunk = []
    current_size = 0

    for line in lines:
        line_size = len(line) + 1  # +1 for newline
        if current_size + line_size > max_chunk and current_chunk:
            chunks.append('\n'.join(current_chunk))
            current_chunk = [line]
            current_size = line_size
        else:
            current_chunk.append(line)
            current_size += line_size

    if current_chunk:
        chunks.append('\n'.join(current_chunk))

    return chunks


def embed_prompt(input_path: str, output_path: str, force: bool = False) -> bool:
    if not force and not needs_regeneration(input_path, output_path):
        print(f"Skipping {output_path} (up-to-date)")
        return False

    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Use short delimiter (MSVC max is 16 chars)
    delimiter = "PROMPT"

    # Split content for MSVC compatibility
    chunks = split_content(content)

    # Build concatenated string literals
    if len(chunks) == 1:
        string_literal = f'R"{delimiter}({chunks[0]}){delimiter}"'
    else:
        parts = []
        for i, chunk in enumerate(chunks):
            parts.append(f'R"{delimiter}({chunk}){delimiter}"')
        string_literal = '\n    '.join(parts)

    header = f'''// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// Auto-generated from {os.path.basename(input_path)}
// Generated: {datetime.now().isoformat()}
// DO NOT EDIT - regenerate with: python scripts/embed_prompt.py

#pragma once

namespace pdbsql {{

inline constexpr const char* AGENT_PROMPT_TEXT =
    {string_literal};

}} // namespace pdbsql
'''

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(header)

    print(f"Generated {output_path} ({len(content)} bytes, {len(chunks)} chunks)")
    return True


if __name__ == "__main__":
    force = "--force" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--force"]

    if len(args) != 2:
        print(f"Usage: {sys.argv[0]} [--force] <input.md> <output.hpp>")
        sys.exit(1)

    embed_prompt(args[0], args[1], force)
