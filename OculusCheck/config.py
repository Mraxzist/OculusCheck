# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

import re

VERSION = "1.1"
USER_AGENT = f"OculusCheck/{VERSION}"

# ---- MalwareBazaar ----
API_URL_MB = "https://mb-api.abuse.ch/api/v1/"
API_KEY_MB_DEFAULT = "PUT-YOUR-MALWAREBAZAAR-KEY-HERE"

# ---- VirusTotal ----
VT_BASE = "https://www.virustotal.com/api/v3"
API_KEY_VT_DEFAULT = "PUT-YOUR-VT-KEY-HERE"

CSV_FIELDS = [
    "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter",
    "file_name","file_type_guess","mime_type","signature","clamav",
    "vtpercent","imphash","ssdeep","tlsh",
]

HEX_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
NULL = "NULL"
