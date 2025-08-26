# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist
"""
OculusCheck — multi-source IOC lookup (VirusTotal, MalwareBazaar, ...)

Public exports:
- VERSION: semantic version string
- orchestrator helpers: build_sources_from_names, run_sources
"""
from .config import VERSION
from .orchestrator import build_sources_from_names, run_sources

__all__ = ["VERSION", "build_sources_from_names", "run_sources"]
