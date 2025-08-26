# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

from datetime import datetime
from pathlib import Path
from typing import Optional

def default_session_name(prefix: str = "RUN") -> str:
    return f"{prefix}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}"

def ensure_session_dir(dest: str, session_dir: Optional[str]) -> Path:
    base = Path(dest).resolve()
    base.mkdir(parents=True, exist_ok=True)
    name = session_dir or default_session_name()
    path = base / name
    path.mkdir(parents=True, exist_ok=True)
    return path

def source_subdir(session_dir: Path, source_name: str) -> Path:
    p = session_dir / source_name
    p.mkdir(parents=True, exist_ok=True)
    return p
