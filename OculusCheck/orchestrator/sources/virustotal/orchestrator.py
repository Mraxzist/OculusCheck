# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Mraxzist

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ....config import API_KEY_VT_DEFAULT, NULL
from ....session import source_subdir
from ....util import collect_items_from_inputs, is_hex_hash
from ...types import BaseSource
from .api import vt_get_file


class VirusTotalSource(BaseSource):
    def __init__(self) -> None:
        self._name = "virustotal"

    @property
    def name(self) -> str:
        return self._name
    # In dev. In the future, there will be a search by ip, domainб url
    def supported_modes(self):
        return ["hash"]

    # ---------- helpers ----------
    @staticmethod
    def _save_json(obj: Any, path: Path, compact: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            if compact:
                json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
            else:
                json.dump(obj, f, ensure_ascii=False, indent=2)

    @staticmethod
    def _build_output_json(query_hash: str, vt_obj: Optional[Dict[str, Any]], error: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        now_utc = datetime.now(timezone.utc).isoformat()
        out: Dict[str, Any] = {
            "schema": "vt-hash-lookup@1.2",
            "queried_at_utc": now_utc,
            "input": {"hash": query_hash, "method": "GET /files/{hash}"},
            "result": {},
            "vt_raw": None,
        }
        if error:
            out["result"] = {"found": False, "error": error}
            return out

        out["vt_raw"] = vt_obj
        data = vt_obj.get("data", {}) if isinstance(vt_obj, dict) else {}
        attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
        file_id = data.get("id")
        obj_type = data.get("type")

        stats = attrs.get("last_analysis_stats", {}) or {}
        totals = sum(int(stats.get(k, 0)) for k in (
            "harmless", "malicious", "suspicious",
            "undetected", "timeout", "type-unsupported", "failure"
        ))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        sha256 = attrs.get("sha256") or file_id or query_hash
        vt_ui_link = f"https://www.virustotal.com/gui/file/{sha256}"

        out["result"] = {
            "found": True,
            "id": file_id,
            "type": obj_type,
            "vt_ui_link": vt_ui_link,
            "detections": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "timeout": int(stats.get("timeout", 0)),
                "type_unsupported": int(stats.get("type-unsupported", 0)),
                "failure": int(stats.get("failure", 0)),
                "total": totals,
            },
            "timeline": {
                "first_submission_date": attrs.get("first_submission_date"),
                "last_submission_date": attrs.get("last_submission_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
            },
            "submissions": {
                "times_submitted": attrs.get("times_submitted"),
                "total_votes": attrs.get("total_votes"),
                "reputation": attrs.get("reputation"),
            },
            "identifiers": {
                "md5": attrs.get("md5"),
                "sha1": attrs.get("sha1"),
                "sha256": attrs.get("sha256"),
                "ssdeep": attrs.get("ssdeep"),
                "tlsh": attrs.get("tlsh"),
                "vhash": attrs.get("vhash"),
                "imphash": (attrs.get("pe_info") or {}).get("imphash"),
            },
            "file_info": {
                "size": attrs.get("size"),
                "type_description": attrs.get("type_description"),
                "type_tag": attrs.get("type_tag"),
                "magic": attrs.get("magic"),
                "names": attrs.get("names"),
                "meaningful_name": attrs.get("meaningful_name"),
                "tags": attrs.get("tags"),
                "packers": attrs.get("packers"),
            },
            "last_analysis_results": attrs.get("last_analysis_results"),
            "pe_info": attrs.get("pe_info"),
            "elf_info": attrs.get("elf_info"),
            "mach-o": attrs.get("mach-o"),
            "crowdsourced_yara_results": attrs.get("crowdsourced_yara_results"),
            "crowdsourced_ai_results": attrs.get("crowdsourced_ai_results"),
            "trid": attrs.get("trid"),
        }
        return out

    @staticmethod
    def _build_summary_entry(query_hash: str, detailed_json: Dict[str, Any], not_found: bool = False) -> Dict[str, Any]:
        if not_found:
            return {
                "input_hash": query_hash,
                "found": False,
                "vt_ui_link": NULL,
                "file_name": NULL,
                "identifiers": {
                    "md5": NULL, "sha1": NULL, "sha256": NULL,
                    "ssdeep": NULL, "tlsh": NULL, "vhash": NULL, "imphash": NULL
                },
                "detections": {
                    "malicious": NULL, "suspicious": NULL, "harmless": NULL,
                    "undetected": NULL, "timeout": NULL,
                    "type_unsupported": NULL, "failure": NULL, "total": NULL
                }
            }

        res = detailed_json.get("result", {}) or {}
        ids = res.get("identifiers", {}) or {}
        det = res.get("detections", {}) or {}
        file_info = res.get("file_info", {}) or {}
        file_name = file_info.get("meaningful_name") or (file_info.get("names") or [None])[0]

        return {
            "input_hash": query_hash,
            "found": True,
            "vt_ui_link": res.get("vt_ui_link"),
            "file_name": file_name,
            "identifiers": {
                "md5": ids.get("md5"),
                "sha1": ids.get("sha1"),
                "sha256": ids.get("sha256"),
                "ssdeep": ids.get("ssdeep"),
                "tlsh": ids.get("tlsh"),
                "vhash": ids.get("vhash"),
                "imphash": ids.get("imphash"),
            },
            "detections": {
                "malicious": det.get("malicious"),
                "suspicious": det.get("suspicious"),
                "harmless": det.get("harmless"),
                "undetected": det.get("undetected"),
                "timeout": det.get("timeout"),
                "type_unsupported": det.get("type_unsupported"),
                "failure": det.get("failure"),
                "total": det.get("total"),
            }
        }

    # ---------- entry ----------
    def run(self, *, args, session_dir: Path):
        vt_dir = source_subdir(session_dir, self.name)

        # API key
        api_key = (
            getattr(args, "api_key_virustotal", None)
            or getattr(args, "vt_api_key", None)
            or API_KEY_VT_DEFAULT
        )
        if not api_key or api_key == "PUT-YOUR-VT-KEY-HERE":
            print("[VT] Missing API key (--api-key-virustotal). Skipping VT.", file=sys.stderr)
            return {"processed": 0}

        # unified inputs: -i (files or inline) + optional --hash
        hashes: List[str] = collect_items_from_inputs(getattr(args, "input", []), "hash")
        if getattr(args, "hash_opt", None) and is_hex_hash(args.hash_opt):
            h = args.hash_opt.strip().lower()
            if h not in hashes:
                hashes.append(h)

        if not hashes:
            print("[VT] No valid hashes. Provide -i (file or inline) and/or --hash.", file=sys.stderr)
            return {"processed": 0}

        print(f"[VT] Processing {len(hashes)} hash(es)…", file=sys.stderr)

        all_check = {
            "schema": "vt-hash-lookup-all@1.1",
            "created_at_local": datetime.now().isoformat(),
            "count": 0,
            "items": []
        }
        processed = 0
        quota_stop = False

        for qh in hashes:
            try:
                resp = vt_get_file(qh, api_key)
            except Exception as ex:
                print(f"[VT] Network error for {qh}: {ex}", file=sys.stderr)
                all_check["items"].append(self._build_summary_entry(qh, {}, not_found=True))
                continue

            # ----- quota / plan notices -----
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                rem = resp.headers.get("X-RateLimit-Remaining")
                lim = resp.headers.get("X-RateLimit-Limit")
                reset = resp.headers.get("X-RateLimit-Reset")
                hint = f"[VT] 429 Too Many Requests — likely quota exhausted. Retry-After: {ra or '?'}s."
                if rem or lim:
                    hint += f" Remaining: {rem or '?'} / {lim or '?'}."
                if reset:
                    hint += f" Reset (epoch): {reset}."
                print(hint, file=sys.stderr)
                quota_stop = True
                break

            if resp.status_code == 403:
                msg = ""
                try:
                    msg = (resp.json().get("error") or {}).get("message") or ""
                except Exception:
                    pass
                print(f"[VT] 403 Forbidden — plan may not permit this endpoint or quota exhausted. {('Message: ' + msg) if msg else ''}", file=sys.stderr)
                quota_stop = True
                break
            # --------------------------------

            if resp.status_code == 404:
                detailed = self._build_output_json(qh, vt_obj=None, error={"code": 404, "message": "not found"})
                self._save_json(detailed, vt_dir / f"{qh}.vt.notfound.json", compact=False)
                all_check["items"].append(self._build_summary_entry(qh, detailed, not_found=True))
                processed += 1
                continue

            if resp.status_code == 401:
                print("[VT] 401 Unauthorized — check API key. Stopping VT.", file=sys.stderr)
                break

            if resp.status_code != 200:
                print(f"[VT] {qh}: unexpected {resp.status_code} {resp.text[:200]}", file=sys.stderr)
                all_check["items"].append(self._build_summary_entry(qh, {}, not_found=True))
                processed += 1
                continue

            vt_obj = resp.json()
            detailed = self._build_output_json(qh, vt_obj=vt_obj, error=None)
            sha_for_name = detailed.get("result", {}).get("identifiers", {}).get("sha256") or qh
            self._save_json(detailed, vt_dir / f"{sha_for_name}.vt.json", compact=False)

            entry = self._build_summary_entry(qh, detailed, not_found=False)
            all_check["items"].append(entry)

            det = detailed["result"].get("detections", {}) or {}
            if (det.get("malicious", 0) or 0) + (det.get("suspicious", 0) or 0) >= 1:
                print(detailed["result"]["vt_ui_link"])  # STDOUT

            processed += 1

        # save All_check regardless of stop reason
        all_check["count"] = len(all_check["items"])
        self._save_json(all_check, vt_dir / "All_check.json", compact=False)

        if quota_stop:
            print(f"[VT] Stopped due to quota/plan limits. Partial results saved: {vt_dir}", file=sys.stderr)
        else:
            print(f"[VT] Done. Directory: {vt_dir}", file=sys.stderr)

        return {"processed": processed, "written": str(vt_dir)}
