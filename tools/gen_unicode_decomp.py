#!/usr/bin/env python3
"""
Generate the NFD canonical decomposition table for normalize.rs from
UnicodeData.txt (Unicode 15.1).

Output: a sorted array of (code_point, decomposition_str) pairs as Rust source.
Also generates the composition table (reverse mapping for NFC).

Usage:
    python3 tools/gen_unicode_decomp.py tools/UnicodeData.txt
"""

import sys

def parse_unicode_data(path):
    """Extract canonical decomposition mappings from UnicodeData.txt."""
    decomp_map = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(';')
            if len(parts) < 6:
                continue
            code = int(parts[0], 16)
            decomp_field = parts[5].strip()
            if not decomp_field:
                continue
            # Skip compatibility decompositions (tagged with <...>)
            if decomp_field.startswith('<'):
                continue
            # Parse the decomposition into code points
            chars = decomp_field.split()
            if len(chars) < 2:
                continue  # singleton decomposition is not canonical
            decomp = ''.join(chr(int(c, 16)) for c in chars)
            decomp_map[code] = decomp
    return decomp_map

def generate_decomp_table(decomp_map):
    """Generate a sorted array of (cp, decomp) for binary search."""
    sorted_cps = sorted(decomp_map.keys())
    lines = []
    lines.append("// Auto-generated from UnicodeData.txt (Unicode 15.1).")
    lines.append("// DO NOT EDIT MANUALLY.")
    lines.append("//")
    lines.append(f"// {len(sorted_cps)} canonical decomposition mappings.")
    lines.append("")
    lines.append("const DECOMP_TABLE: &[(u32, &str)] = &[")

    for cp in sorted_cps:
        decomp = decomp_map[cp]
        # Escape the decomp string for Rust source
        escaped = decomp.encode('unicode_escape').decode('ascii')
        lines.append(f"    (0x{cp:04X}, \"{decomp}\"),")

    lines.append("];")
    return '\n'.join(lines)

def generate_comp_table(decomp_map):
    """Generate composition table (reverse mapping: decomp → composed)."""
    comp_map = {}
    for cp, decomp in decomp_map.items():
        # Composition only applies to decompositions of exactly 2 chars
        if len(decomp) == 2:
            key = (ord(decomp[0]), ord(decomp[1]))
            comp_map[key] = cp
    sorted_keys = sorted(comp_map.keys())
    lines = []
    lines.append("// Auto-generated composition table (NFC).")
    lines.append("// {len(sorted_keys)} entries.")
    lines.append("")
    lines.append("const COMP_TABLE: &[(u32, u32, u32)] = &[")

    for (base, comb) in sorted_keys:
        composed = comp_map[(base, comb)]
        lines.append(f"    (0x{base:04X}, 0x{comb:04X}, 0x{composed:04X}),")

    lines.append("];")
    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        path = "tools/UnicodeData.txt"
    else:
        path = sys.argv[1]

    decomp_map = parse_unicode_data(path)
    print(f"// Found {len(decomp_map)} canonical decomposition mappings", file=sys.stderr)

    decomp_table = generate_decomp_table(decomp_map)
    comp_table = generate_comp_table(decomp_map)

    # Output both tables as a Rust source file
    print("//! Canonical decomposition and composition tables for Unicode NFD/NFC.")
    print("//! Auto-generated. Do not edit.")
    print()
    print("#[allow(dead_code)]")
    print(decomp_table)
    print()
    print("#[allow(dead_code)]")
    print(comp_table)

if __name__ == '__main__':
    main()
