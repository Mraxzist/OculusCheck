# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

from pathlib import Path
from typing import List
from .config import HEX_RE

def is_hex_hash(s: str) -> bool:
    if not s:
        return False
    if not all(c in "0123456789abcdefABCDEF" for c in s):
        return False
    return len(s) in (32, 40, 64)  # MD5/SHA1/SHA256

def read_lines_file(p: Path) -> List[str]:
    items: List[str] = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            if line:
                items.append(line)
    return items

def read_hashes_file(p: Path) -> List[str]:
    out: List[str] = []
    for line in read_lines_file(p):
        if is_hex_hash(line):
            out.append(line.lower())
    return out

def parse_hashes_from_texts(values: List[str]) -> List[str]:
    out, seen = [], set()
    for raw in values or []:
        for m in HEX_RE.finditer(raw):
            h = m.group(1).lower()
            if h not in seen:
                seen.add(h)
                out.append(h)
    return out

def split_values(values: List[str]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        if "," in v:
            parts = [p.strip().strip('"').strip("'") for p in v.split(",")]
            out.extend([p for p in parts if p])
        else:
            out.append(v.strip().strip('"').strip("'"))
    seen, final = set(), []
    for x in out:
        if x and x not in seen:
            seen.add(x)
            final.append(x)
    return final

def collect_items_from_inputs(inputs: List[str], mode: str) -> List[str]:
    items: List[str] = []
    for arg in inputs or []:
        p = Path(arg)
        if p.exists() and p.is_file():
            if mode == "hash":
                items.extend(read_hashes_file(p))
            else:
                items.extend(read_lines_file(p))
        else:
            if mode == "hash":
                items.extend(parse_hashes_from_texts([arg]))
            else:
                items.extend(split_values([arg]))
    seen, out = set(), []
    for x in items:
        if not x:
            continue
        if mode == "hash":
            if not is_hex_hash(x):
                continue
            x = x.lower()
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
