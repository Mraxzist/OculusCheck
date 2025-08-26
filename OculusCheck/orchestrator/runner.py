# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

import sys
import traceback
from pathlib import Path
from typing import List

from .types import BaseSource
from .sources import SOURCE_REGISTRY  # name -> class


def _expand_names(names: List[str]) -> List[str]:
    expanded: List[str] = []
    for n in names or []:
        if n == "all":
            expanded.extend(["virustotal", "malwarebazaar"])
        else:
            expanded.append(n)

    order: List[str] = []
    for candidate in ("virustotal", "malwarebazaar"):
        if candidate in expanded and candidate not in order:
            order.append(candidate)
    # In dev. There will be new sources in the future
    for n in expanded:
        if n not in order:
            order.append(n)
    return order


def build_sources_from_names(names: List[str]) -> List[BaseSource]:
    out: List[BaseSource] = []
    for n in _expand_names(names):
        cls = SOURCE_REGISTRY.get(n)
        if not cls:
            print(f"[orchestrator] Unknown source: {n}", file=sys.stderr)
            continue
        try:
            out.append(cls())
        except Exception as e:
            print(f"[orchestrator] Failed to init source '{n}': {e}", file=sys.stderr)
    return out


def run_sources(sources: List[BaseSource], *, args, session_dir: Path) -> None:
    """
    execute sources
    """
    for src in sources:
        try:
            stats = src.run(args=args, session_dir=session_dir)
            if stats:
                print(f"[orchestrator] {src.name} finished: {stats}", file=sys.stderr)
        except SystemExit:
            # We allow the source to terminate the process intentionally (e.g. at 401).
            raise
        except Exception as e:
            print(f"[orchestrator] {src.name} crashed: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
