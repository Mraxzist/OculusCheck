# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

import argparse
import sys
from pathlib import Path

from . import VERSION
from .session import ensure_session_dir
from .orchestrator import build_sources_from_names, run_sources

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="OculusCheck",
        description=f"OculusCheck v{VERSION}: multi-source IOC lookup (VirusTotal, MalwareBazaar)"
    )

    ap.add_argument(
        "--source", nargs="+",
        choices=["virustotal", "malwarebazaar", "all"],
        default=["malwarebazaar"],
        help="Which source(s) to run. 'all' = virustotal then malwarebazaar."
    )

    ap.add_argument("--dest", default=".", help="Base directory for session outputs (default: current).")
    ap.add_argument("--session-dir", help="Session folder name (default: RUN_YYYY-mm-dd_HHMMSS).")

    ap.add_argument(
        "-i", "--input", action="append", default=[],
        help=("Input values. Each -i can be a FILE path or an inline string. "
              "For mode=hash we auto-extract MD5/SHA1/SHA256 from inline text; "
              "for signature/name we split by commas/spaces. Repeat -i as needed.")
    )
    ap.add_argument(
        "--hash", dest="hash_opt",
        help="Single MD5/SHA1/SHA256 (applies to all sources when relevant)."
    )

    # MalwareBazaar options
    ap.add_argument("-m", "--mode", choices=["hash", "signature", "name"], default="hash",
                    help="MB mode: hash/signature/name (used when malwarebazaar is selected).")
    ap.add_argument("--limit", type=int, default=200, help="MB: limit for signature mode (<=1000).")
    ap.add_argument("--recent-selector", default="100", choices=["time", "100"], help="MB: recent selector for name mode.")

    # Networking
    ap.add_argument("--connect-timeout", type=float, default=10.0)
    ap.add_argument("--read-timeout", type=float, default=45.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--backoff", type=float, default=1.0)
    ap.add_argument("--proxy")
    ap.add_argument("--verify", action="store_true", default=True)
    ap.add_argument("--no-verify", action="store_false", dest="verify")

    # API keys
    ap.add_argument("--api-key-virustotal", dest="api_key_virustotal", help="VirusTotal API key.")
    ap.add_argument("--vt-api-key", dest="vt_api_key", help="Alias for --api-key-virustotal.")
    ap.add_argument("--api-key-malwarebazaar", dest="api_key_malwarebazaar", help="MalwareBazaar API key.")
    ap.add_argument("--mb-api-key", dest="mb_api_key", help="Alias for --api-key-malwarebazaar.")
    ap.add_argument("--api-key", dest="api_key", help="(compat) used as MB key if --api-key-malwarebazaar not provided.")

    return ap

def main():
    ap = build_parser()
    args = ap.parse_args()

    sdir = ensure_session_dir(args.dest, args.session_dir)

    srcs = build_sources_from_names(args.source)
    if not srcs:
        print("No sources selected. Use --source virustotal|malwarebazaar|all", file=sys.stderr)
        sys.exit(2)

    run_sources(srcs, args=args, session_dir=Path(sdir))
    print(f"[i] Session directory: {sdir}", file=sys.stderr)

if __name__ == "__main__":
    main()
