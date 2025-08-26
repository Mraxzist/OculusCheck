# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

from dataclasses import dataclass
from typing import Dict, Optional

@dataclass
class LiveCtx:
    mode: str      # "table" | "ndjson" | "csv"
    printed_header: bool = False
    counter: int = 0

def live_init(mode: str = "table") -> LiveCtx:
    return LiveCtx(mode=mode, printed_header=False, counter=0)

def _fmt_table_row(row: Dict) -> str:
    fs = (row.get("first_seen_utc") or "")[:19]
    sha = (row.get("sha256_hash") or "")[:12]
    name = (row.get("file_name") or "")[:40]
    sig = (row.get("signature") or "")[:24]
    vt = str(row.get("vtpercent") or "")
    return f"{fs:19}  {sha:12}  {name:40}  {sig:24}  {vt:>4}"

def live_emit_row(ctx: LiveCtx, row: Dict) -> None:
    if ctx.mode == "ndjson":
        import json
        print(json.dumps(row, ensure_ascii=False))
        return
    if ctx.mode == "csv":
        import csv, sys
        w = csv.DictWriter(sys.stdout, fieldnames=list(row.keys()))
        if not ctx.printed_header:
            w.writeheader()
            ctx.printed_header = True
        w.writerow(row)
        return
    # default: table
    if not ctx.printed_header:
        print("first_seen_utc       sha256        file_name                               signature                 vt%")
        print("-"*100)
        ctx.printed_header = True
    print(_fmt_table_row(row))
    ctx.counter += 1
