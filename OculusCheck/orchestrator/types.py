# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Sequence


class BaseSource(ABC):
    """
    The common interface of the "source" (VirusTotal, MalwareBazaar, ...).

        Each source must:
    - have a unique name (property `name`);
          - declare supported modes (`supported_modes');
          - implement `run(args=args, session_dir=Path)` and
    write your artifacts inside `<session_dir>/<source_name>/...`.
    - return short statistics (dict) — at the discretion of the source.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """The unique machine name of the source (e.g., 'virustotal')."""

    @abstractmethod
    def supported_modes(self) -> Sequence[str]:
        """A list of modes that the source understands (e.g. ['hash'])."""

    @abstractmethod
    def run(self, *, args: Any, session_dir: Path) -> Dict[str, Any]:
        """
          Launch the source. Must create the `<session_dir>/<name>/` himself
                  and put the result files there. Returns brief statistics.
        """
