# OculusCheck — поиск хэшей в базах вредоносных файлов.

[English](README.md) | **Русский**

---

## 🎯 Назначение

**OculusCheck** — инструмент для **обогащения индикаторов** и **быстрой проверки артефактов** в процессах TI/DFIR/SOC.  
Он помогает понять **что это за файл**, когда он **впервые замечен**, к какой **семье/сигнатуре** относится, и собрать полезные атрибуты (MIME, ClamAV, VT%, imphash, ssdeep, tlsh и т.д.) — **без скачивания и запуска** образцов.

### Возможное использование
- 🧪 **Malware-research:** подбор образцов по сигнатуре/семейству для исследований.
- 🔍 **Hunting / Threat Intel:** проверка хэшей на известность/вредоносность.
- 🕵️ **DFIR / Incident Response:** быстрое обогащение хэшей/файлов из тикетов..

**Источники**
  - `--source virustotal` — репутация файла по хэшу (MD5/SHA1/SHA256).
  - `--source malwarebazaar` — поиск по хэшам/сигнатурам/имени файла.
  - `--source all` — последовательный запуск **VirusTotal → MalwareBazaar**.

**Сохранение результатов**
  - **VirusTotal**: `virustotal/All_check.json`, `<sha256>.vt.json`, `<hash>.vt.notfound.json`.  
  - **MalwareBazaar**: ВСЕГДА два файла — `malwarebazaar/mb_results.csv` и `malwarebazaar/mb_results.json`.

### Чего утилита **не** делает
- ⛔ **Не скачивает и не запускает** вредоносные образцы.
- ⛔ **Не обходит** лимиты/политику abuse.ch, **не** является антивирусом или песочницей.
- ⛔ **Не гарантирует** наличие всех полей в каждом ответе (часть атрибутов опциональна на стороне источника).
- ⛔ **Не даёт гарантии**, что если хэш **не найден** в базе, то соответствующий файл **безвреден**.

### Ограничения и нюансы
- 📉 **Лимиты API**: возможны `HTTP 429` и заголовки `X-RateLimit-*`. Инструмент выводит понятные предупреждения и поддерживает бэк-офф/повторы.
- 🌐 В корпоративных сетях с прокси/TLS-инспекцией может понадобиться `--proxy` и/или `--no-verify`.


---

## 🧯 Troubleshooting

* «Пусто / нет вывода»: проверьте, что указали `--source` и корректный `-i/--input` (файл существует) или `--hash`.
* VT: `401` — проверьте ключ; `429/403` — исчерпан лимит/недоступен эндпойнт на тарифе.
* MB: «No hashes» — для `-m hash` подайте хэши через `-i` (файл или inline) и/или `--hash`.

---

### Дисклеймер ⚠️
Инструмент предназначен **исключительно для легитимных исследований, обучения и обороны** в рамках закона и локальных политик.  
Вы лично отвечаете за дальнейшее **скачивание/обращение/запуск** образцов и соблюдение всех юридических и лицензионных требований. Автор ответственности не несёт.
---


---

## ✨ Возможности

**Источники**
- `--source virustotal` — репутация файла по хэшу (MD5/SHA1/SHA256).
- `--source malwarebazaar` — поиск по хэшам/сигнатурам/имени файла.
- `--source all` — последовательный запуск **VirusTotal → MalwareBazaar** (приоритет VT).

**Единый ввод**
- `-i/--input` — универсальный вход: **путь к файлу** *или* **inline-строка**. Ключ можно повторять.  
  Для `-m hash` из текста автоматически извлекаются MD5/SHA1/SHA256.  
  Для `signature`/`name` значения делятся по запятым/пробелам.
- `--hash <MD5|SHA1|SHA256>` — добавить одиночный хэш.

**Сохранение результатов**
- **VirusTotal:** `virustotal/All_check.json`, `<sha256>.vt.json`, `<hash>.vt.notfound.json`.
- **MalwareBazaar:** **всегда** два файла — `malwarebazaar/mb_results.csv` и `malwarebazaar/mb_results.json`.

**Режимы MalwareBazaar**
- `-m hash` — `get_info` по хэшам (смешанные MD5/SHA1/SHA256).
- `-m signature` — `get_siginfo` (до 1000 последних).
- `-m name` — фильтрация по именам по **recent** (`time` или `100`); у MB нет родного filename-поиска через API.

**Сеть/устойчивость**
- Таймауты, ретраи с backoff, прокси, опциональная верификация TLS (для MB).
- Для VT выводятся подсказки при 429/403 (Retry-After, X-RateLimit-*).

---


## 🧱 Структура проекта

```

OculusCheck/
├─ OculusCheck/
│  ├─ __init__.py
│  ├─ __main__.py               # единый CLI (python -m OculusCheck)
│  ├─ config.py                 # константы, VERSION, дефолтные ключи
│  ├─ session.py                # <dest>/<session>/..., подпапки источников
│  ├─ util.py                   # парсинг/валидация, единый сбор из -i
│  ├─ preview.py                # (на будущее) live-просмотр
│  └─ orchestrator/
│     ├─ __init__.py
│     ├─ types.py               # BaseSource (контракт плагина-источника)
│     ├─ runner.py              # порядок и запуск источников (VT → MB)
│     └─ sources/
│        ├─ __init__.py         # реестр: name -> класс
│        ├─ virustotal/
│        │  ├─ __init__.py
│        │  ├─ api.py
│        │  └─ orchestrator.py
│        └─ malwarebazaar/
│           ├─ __init__.py
│           ├─ api.py
│           ├─ core.py
│           └─ orchestrator.py
├─ LICENSE
├─ README.md
└─ README.ru.md

```

---

## ⚙️ Установка

```bash
git clone https://github.com/Mraxzist/OculusCheck.git
cd OculusCheck
python -m pip install -r requirements.txt
````

---

## 🔐 API-ключи

Укажите ключи через CLI или задайте дефолты в `OculusCheck/config.py`:

```python
API_KEY_VT_DEFAULT = "YOUR-VT-KEY"  # VirusTotal
API_KEY_MB_DEFAULT = "YOUR-MB-KEY"  # MalwareBazaar
```

CLI-варианты:

* `--api-key-virustotal` (алиас `--vt-api-key`)
* `--api-key-malwarebazaar` (алиас `--mb-api-key`; совместимый `--api-key` — тоже для MB)
---

---

## 🛠 Параметры CLI

| Ключ                                      | Описание                                                        |
| ----------------------------------------- | --------------------------------------------------------------- |
| `--source`                                | `virustotal` \| `malwarebazaar` \| `all` (при `all`: VT → MB)   |
| `-i, --input`                             | Вход: **файл** *или* **inline-строка**. Повторяемый.            |
| `--hash`                                  | Добавить одиночный MD5/SHA1/SHA256.                             |
| `-m, --mode`                              | Для MB: `hash` \| `signature` \| `name` (по умолчанию `hash`).  |
| `--limit`                                 | MB/signature: лимит (≤1000).                                    |
| `--recent-selector`                       | MB/name: `time` (последний час) или `100` (последние 100).      |
| `--api-key-virustotal`, `--vt-api-key`    | API-ключ VirusTotal.                                            |
| `--api-key-malwarebazaar`, `--mb-api-key` | API-ключ MalwareBazaar (совместимый `--api-key` — тоже для MB). |
| `--connect-timeout`, `--read-timeout`     | Таймауты запросов (MB).                                         |
| `--retries`, `--backoff`                  | Повторы и коэффициент задержки (MB).                            |
| `--proxy`                                 | Прокси `http(s)://host:port`.                                   |
| `--verify` / `--no-verify`                | Включить/выключить проверку TLS (MB).                           |

---

## 🏃 Запуск

**VirusTotal** (хэши из файла + один хэш):

```bash
python -m OculusCheck --source virustotal \
  --api-key-virustotal VT_KEY \
  -i hashes.txt --hash 2b0af18bdd10782c...
```

**MalwareBazaar** (по хэшам — файл или inline):

```bash
python -m OculusCheck --source malwarebazaar \
  --api-key-malwarebazaar MB_KEY \
  -m hash -i hashes.txt -i "44d8..., 7f3e..."
```

**Оба источника сразу**:

```bash
python -m OculusCheck --source all \
  --api-key-virustotal VT_KEY \
  --api-key-malwarebazaar MB_KEY \
  -i hashes.txt --hash 2b0af18bdd10782c...
```

## 🔒 Безопасность

* Относитесь к выводимым данным как к чувствительному TI. 🛡️

---

---

## 🗺 Планы/идеи

* **Новые типы индикаторов:** IP, домены, URL (подкаталоги `orchestrator/sources/ip|domain|url` + провайдеры: AbuseIPDB, URLHaus, OTX, PassiveDNS и т.д.).
* **Глобальный ключ `--indicator`** (`file_hash|ip|domain|url`) с выбором источников в рамках индикатора.
* **JSON-схемы** результатов (`schemas/*.json`) и валидация.
* **Юнит-тесты** для утилит и источников.

---


## License

Этот проект лицензирован по лицензии mit — смотрите [LICENSE](./LICENSE) файл с подробностями.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
