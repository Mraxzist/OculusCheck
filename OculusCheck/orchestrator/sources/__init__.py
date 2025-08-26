# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

from .malwarebazaar import MalwareBazaarSource
from .virustotal import VirusTotalSource

SOURCE_REGISTRY = {
    "malwarebazaar": MalwareBazaarSource,
    "virustotal": VirusTotalSource,
}

__all__ = ["SOURCE_REGISTRY", "MalwareBazaarSource", "VirusTotalSource"]
