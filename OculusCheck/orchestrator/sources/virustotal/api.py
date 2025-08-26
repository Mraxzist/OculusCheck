# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

import time
from typing import Optional
import requests

from ....config import VT_BASE

def vt_get_file(hash_value: str, api_key: str, *, retry_once_on_429: bool = True, timeout: int = 30) -> requests.Response:
    """
    GET /files/{hash} with optional single retry on HTTP 429 (using Retry-After).
    """
    url = f"{VT_BASE}/files/{hash_value}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=timeout)
    if resp.status_code == 429 and retry_once_on_429:
        wait_s = int(resp.headers.get("Retry-After", "15") or "15")
        time.sleep(max(1, wait_s))
        resp = requests.get(url, headers=headers, timeout=timeout)
    return resp
