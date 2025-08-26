# OculusCheck — searching hashes in malware databases

**English** | [Русский](README.ru.md)

---

## 🎯 Purpose

**OculusCheck** is a tool for **indicator enrichment** and **rapid artifact checks** in TI/DFIR/SOC workflows.  
It helps you understand **what a file is**, when it was **first seen**, which **family/signature** it belongs to, and collect useful attributes (MIME, ClamAV, VT%, imphash, ssdeep, tlsh, etc.) — **without downloading or executing** samples.

### Possible uses
- 🧪 **Malware research:** assembling samples by signature/family for research.
- 🔍 **Hunting / Threat Intel:** checking hashes for known/malicious status.
- 🕵️ **DFIR / Incident Response:** quick enrichment of hashes/files from tickets.

**Sources**
  - `--source virustotal` — file reputation by hash (MD5/SHA1/SHA256).
  - `--source malwarebazaar` — search by hashes/signatures/filename.
  - `--source all` — sequential run **VirusTotal → MalwareBazaar**.

**Result saving**
  - **VirusTotal**: `virustotal/All_check.json`, `<sha256>.vt.json`, `<hash>.vt.notfound.json`.  
  - **MalwareBazaar**: ALWAYS two files — `malwarebazaar/mb_results.csv` and `malwarebazaar/mb_results.json`.

### What the tool **does not** do
- ⛔ **Does not download or execute** malicious samples.
- ⛔ **Does not bypass** abuse.ch limits/policies, and is **not** an antivirus or sandbox.
- ⛔ **Does not guarantee** all fields will be present in every response (some attributes are optional upstream).
- ⛔ **Does not guarantee** that if a hash is **not found** in the database, the corresponding file is **benign**.

### Limits & caveats
- 📉 **API limits**: you may see `HTTP 429` and `X-RateLimit-*` headers. The tool prints clear warnings and supports back-off/retries.
- 🌐 In corporate networks with proxies/TLS inspection you may need `--proxy` and/or `--no-verify`.

---

## 🧯 Troubleshooting

* “No output / looks empty”: ensure you passed `--source` and a valid `-i/--input` (file exists) or `--hash`.
* VT: `401` — check your key; `429/403` — quota exhausted / endpoint not available on your plan.
* MB: “No hashes” — for `-m hash` provide hashes via `-i` (file or inline) and/or `--hash`.

---

### Disclaimer ⚠️
This tool is intended **solely for legitimate research, education, and defense**, in accordance with applicable laws and local policies.  
You are personally responsible for any **downloading/handling/execution** of samples and for complying with all legal and licensing requirements. The author assumes no liability.
---

---

## ✨ Features

**Sources**
- `--source virustotal` — file reputation by hash (MD5/SHA1/SHA256).
- `--source malwarebazaar` — search by hashes/signatures/filename.
- `--source all` — sequential run **VirusTotal → MalwareBazaar** (VT priority).

**Unified input**
- `-i/--input` — universal input: **file path** *or* **inline string**. May be repeated.  
  For `-m hash`, MD5/SHA1/SHA256 are auto-extracted from text.  
  For `signature`/`name`, values are split by commas/spaces.
- `--hash <MD5|SHA1|SHA256>` — add a single hash.

**Result saving**
- **VirusTotal:** `virustotal/All_check.json`, `<sha256>.vt.json`, `<hash>.vt.notfound.json`.
- **MalwareBazaar:** **always** two files — `malwarebazaar/mb_results.csv` and `malwarebazaar/mb_results.json`.

**MalwareBazaar modes**
- `-m hash` — `get_info` by hashes (mixed MD5/SHA1/SHA256).
- `-m signature` — `get_siginfo` (up to the latest 1000).
- `-m name` — filename filtering via **recent** (`time` or `100`); MB has no native filename search API.

**Networking/resilience**
- Timeouts, retries with backoff, proxy, optional TLS verification (for MB).
- For VT, hints are printed on 429/403 (Retry-After, X-RateLimit-*).

---

## 🧱 Project structure

```

OculusCheck/
├─ OculusCheck/
│  ├─ **init**.py
│  ├─ **main**.py               # single CLI (python -m OculusCheck)
│  ├─ config.py                 # constants, VERSION, default keys
│  ├─ session.py                # <dest>/<session>/..., per-source subfolders
│  ├─ util.py                   # parsing/validation, unified -i collector
│  ├─ preview\.py                # (future) live preview
│  └─ orchestrator/
│     ├─ **init**.py
│     ├─ types.py               # BaseSource (plugin contract)
│     ├─ runner.py              # order & execution (VT → MB)
│     └─ sources/
│        ├─ **init**.py         # registry: name -> class
│        ├─ virustotal/
│        │  ├─ **init**.py
│        │  ├─ api.py
│        │  └─ orchestrator.py
│        └─ malwarebazaar/
│           ├─ **init**.py
│           ├─ api.py
│           ├─ core.py
│           └─ orchestrator.py
├─ LICENSE
├─ README.md
└─ README.ru.md

````

---

## ⚙️ Install

```bash
git clone https://github.com/Mraxzist/OculusCheck.git
cd OculusCheck
python -m pip install -r requirements.txt
````

---

## 🔐 API keys

Provide keys via CLI or set defaults in `OculusCheck/config.py`:

```python
API_KEY_VT_DEFAULT = "YOUR-VT-KEY"  # VirusTotal
API_KEY_MB_DEFAULT = "YOUR-MB-KEY"  # MalwareBazaar
```

CLI variants:

* `--api-key-virustotal` (alias `--vt-api-key`)
* `--api-key-malwarebazaar` (alias `--mb-api-key`; compatible `--api-key` is also for MB)

---

---

## 🛠 CLI options

| Option                                    | Description                                                   |
| ----------------------------------------- | ------------------------------------------------------------- |
| `--source`                                | `virustotal` \| `malwarebazaar` \| `all` (for `all`: VT → MB) |
| `-i, --input`                             | Input: **file** *or* **inline string**. Repeatable.           |
| `--hash`                                  | Add a single MD5/SHA1/SHA256.                                 |
| `-m, --mode`                              | For MB: `hash` \| `signature` \| `name` (default `hash`).     |
| `--limit`                                 | MB/signature: limit (≤1000).                                  |
| `--recent-selector`                       | MB/name: `time` (last hour) or `100` (last 100).              |
| `--api-key-virustotal`, `--vt-api-key`    | VirusTotal API key.                                           |
| `--api-key-malwarebazaar`, `--mb-api-key` | MalwareBazaar API key (compatible `--api-key` also for MB).   |
| `--connect-timeout`, `--read-timeout`     | Request timeouts (MB).                                        |
| `--retries`, `--backoff`                  | Retries and backoff factor (MB).                              |
| `--proxy`                                 | Proxy `http(s)://host:port`.                                  |
| `--verify` / `--no-verify`                | Enable/disable TLS verification (MB).                         |

---

## 🏃 Run

**VirusTotal** (hashes from file + one hash):

```bash
python -m OculusCheck --source virustotal \
  --api-key-virustotal VT_KEY \
  -i hashes.txt --hash 2b0af18bdd10782c...
```

**MalwareBazaar** (by hashes — file or inline):

```bash
python -m OculusCheck --source malwarebazaar \
  --api-key-malwarebazaar MB_KEY \
  -m hash -i hashes.txt -i "44d8..., 7f3e..."
```

**Both sources at once:**

```bash
python -m OculusCheck --source all \
  --api-key-virustotal VT_KEY \
  --api-key-malwarebazaar MB_KEY \
  -i hashes.txt --hash 2b0af18bdd10782c...
```

## 🔒 Security

* Treat outputs as sensitive threat intelligence. 🛡️

---

---

## 🗺 Plans / ideas

* **New indicator types:** IP, domains, URL (subfolders `orchestrator/sources/ip|domain|url` + providers like AbuseIPDB, URLHaus, OTX, PassiveDNS, etc.).
* **Global `--indicator`** (`file_hash|ip|domain|url`) with per-indicator source selection.
* **JSON schemas** for results (`schemas/*.json`) and validation.
* **Unit tests** for utilities and sources.

---

## License

This project is licensed under the MIT license — see [LICENSE](./LICENSE) for details.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)