# FileScanner – Local File & URL Security Scanning Engine

FileScanner is a high-performance, modular, and locally hosted file and URL security scanner built with Python 3.11+, FastAPI, PostgreSQL, ClamAV, YARA, Redis, and Celery.

The system empowers security analysts and developers to inspect files, ZIP archives, and website URLs for malware, trojans, ransomware, obfuscated scripts, phishing patterns, and SSRF indicators—**without depending on external third-party scanning APIs** like VirusTotal.

---

## 1. Architecture Overview

```
                      +-----------------------------+
                      |   Client / Postman / UI     |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |    FastAPI Web Service      |
                      |   (Async / Sync Routing)    |
                      +--------------+--------------+
                                     |
            +------------------------+------------------------+
            |                        |                        |
            v                        v                        v
+-----------------------+ +--------------------+ +-----------------------+
|  ClamAV Antivirus     | |  YARA Engine       | |  URL Security Engine  |
|  Daemon (TCP / Socket)| |  (Compiled Rules)  | |  (SSRF Protection)    |
+-----------------------+ +--------------------+ +-----------------------+
            |                        |                        |
            +------------------------+------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |    PostgreSQL Database      |
                      | (ScanHistory, Threats, Rpt) |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | PDF & JSON Report Generator |
                      |    (ReportLab Rendering)    |
                      +-----------------------------+
```

---

## 2. Directory Structure

```
filescanner/
│
├── app/
│   ├── main.py                  # FastAPI application entrypoint & lifespan
│   ├── config.py                # Pydantic Settings & environment variables
│   ├── database.py              # SQLAlchemy engine, session maker & fallback
│   ├── dependencies.py          # Route dependencies (DB sessions)
│   │
│   ├── models/                  # SQLAlchemy ORM Models
│   │   ├── __init__.py
│   │   ├── scan_history.py      # ScanHistory model
│   │   ├── scan_file.py         # ScanFile model
│   │   ├── threat_detection.py  # ThreatDetection model
│   │   └── scan_report.py       # ScanReport model
│   │
│   ├── schemas/                 # Pydantic Validation & Serialization
│   │   ├── scan_schema.py       # Core scan schemas & pagination
│   │   ├── file_schema.py       # File upload & inspection schemas
│   │   └── url_schema.py        # URL request schemas
│   │
│   ├── api/
│   │   └── routes/              # FastAPI Router Endpoints
│   │       ├── health.py        # Health & scanner status routes
│   │       ├── file_scan.py     # File upload & scanning route
│   │       ├── zip_scan.py      # ZIP archive inspection route
│   │       ├── url_scan.py      # URL analysis & SSRF route
│   │       ├── scan_history.py  # Paginated history & scan retrieval
│   │       └── scan_report.py   # Download JSON/PDF report
│   │
│   ├── services/                # Business & Engine Logic
│   │   ├── clamav_service.py    # Native TCP socket protocol client for ClamAV
│   │   ├── yara_service.py      # YARA compiler & rule matching engine
│   │   ├── zip_service.py       # Safe ZIP extractor with bomb & traversal defense
│   │   ├── url_service.py       # URL crawler, HTML parser & SSRF guard
│   │   ├── file_service.py      # File streaming, hashing & MIME identification
│   │   ├── scan_service.py      # Scan coordinator & database persister
│   │   └── report_service.py    # ReportLab PDF & JSON generator
│   │
│   ├── tasks/                   # Celery Asynchronous Workers
│   │   ├── celery_app.py        # Celery application configuration
│   │   └── scan_tasks.py        # Background scanning tasks
│   │
│   └── utils/                   # Security & Helper Utilities
│       ├── file_validation.py   # Magic bytes detection & filename sanitizer
│       ├── hash_utils.py        # Chunked SHA256/MD5 calculation
│       ├── security_utils.py    # SSRF validator & DNS resolver
│       └── response_handler.py  # Standard JSON responses
│
├── yara_rules/                  # Local YARA Signatures
│   └── custom_rules.yar         # Custom detection rules
│
├── uploads/                     # Stored uploads (excluded from git)
├── temp/                        # Ephemeral extraction directories
├── reports/                     # Generated PDF and JSON reports
├── logs/                        # Application log files
│
├── tests/                       # Automated Pytest Suite (23 test cases)
│   ├── conftest.py
│   ├── test_file_scan.py
│   ├── test_zip_scan.py
│   ├── test_url_scan.py
│   └── test_security.py
│
├── postman/                     # Ready-to-import Postman Collection
│   └── FileScanner_Postman_Collection.json
│
├── migrations/                  # Alembic DB Migrations
│   ├── env.py
│   └── versions/
│       └── 001_initial_tables.py
│
├── requirements.txt
├── .env
├── .env.example
├── .gitignore
├── docker-compose.yml
├── alembic.ini
└── README.md
```

---

## 3. Technology Stack

- **Python 3.11+ / 3.14**
- **FastAPI**: Modern, asynchronous web framework for high-throughput endpoints.
- **PostgreSQL & SQLAlchemy 2.0**: Relational persistence for scan histories, files, threats, and reports.
- **Alembic**: Database migrations.
- **ClamAV**: Real-time antivirus daemon scanning via native socket `INSTREAM` protocol.
- **YARA (`yara-python`)**: Malware pattern and heuristic signature engine with reload support.
- **Redis & Celery**: Asynchronous worker task queue for large file scans.
- **ReportLab**: PDF report generation.
- **Docker Compose**: Containerized PostgreSQL, Redis, and ClamAV.

---

## 4. Local Windows Setup Instructions

### Step 1: Create Virtual Environment

PowerShell:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Command Prompt (CMD):
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

### Step 2: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables

Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```

Adjust the values in `.env` as needed:
```ini
APP_NAME=FileScanner
DEBUG=True
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/filescanner_db
REDIS_URL=redis://localhost:6379/0
ASYNC_SCAN_ENABLED=False
CLAMAV_HOST=localhost
CLAMAV_PORT=3310
```

> **Note on Zero-Dependency Development:** If PostgreSQL or Redis are not running, the application automatically uses a local SQLite database (`filescanner.db`) and executes scans synchronously, allowing you to test all endpoints in Postman immediately without any setup hurdles!

### Step 4: Run Supporting Services (Docker)

To run PostgreSQL, Redis, and ClamAV in Docker:
```powershell
docker compose up -d
```

### Step 5: Run Database Migrations

```powershell
alembic upgrade head
```

### Step 6: Start Celery Worker (Optional for Async Scans)

In a separate terminal (with virtual environment activated):
```powershell
celery -A app.tasks.celery_app worker --loglevel=info --pool=solo
```
*(On Windows, `--pool=solo` or `--pool=threads` is recommended for Celery).*

### Step 7: Start the FastAPI Server

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **Swagger Interactive API Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 5. Security & Scanning Capabilities

### File Scanning (`POST /api/scan/file`)
- **Signature & MIME Inspection:** Inspects magic bytes (PDF, ZIP, DOCX, EXE, DLL, scripts, images) rather than trusting file extensions.
- **Sanitized Filenames:** Replaces dangerous path traversals, control characters, and assigns collision-proof server filenames.
- **SHA256 Hash Verification:** Chunk-based cryptographic hashing.
- **ClamAV & YARA Evaluation:** Concurrently analyzes bytes across both engines.

### ZIP Archive Inspection (`POST /api/scan/zip`)
- **ZIP Bomb Defense:** Enforces strict limits on uncompressed extraction size (`MAX_ZIP_EXTRACT_SIZE_MB`), total file count (`MAX_ZIP_FILES`), and compression ratios.
- **Path Traversal Protection:** Validates that members cannot break out of the temporary extraction root directory (`..` or absolute paths).
- **Nested Archive Unpacking:** Recursively scans nested archives up to `MAX_NESTED_ZIP_DEPTH`.
- **Encrypted Archive Detection:** Identifies password-protected archives and flags them as `UNABLE_TO_SCAN`.
- **Automatic Sandbox Cleanup:** All extracted contents are deleted after scan completion.

### URL Security & SSRF Protection (`POST /api/scan/url`)
- **Strict SSRF Mitigation:**
  - Blocks `localhost`, `127.0.0.1`, `::1`.
  - Blocks private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and IPv6 (fc00::/7, fe80::/10) ranges.
  - Blocks Cloud Metadata endpoints (`169.254.169.254`, `metadata.google.internal`, Alibaba, AWS IMDS).
  - Validates DNS before request initiation.
  - Validates **every single redirect destination** hop-by-hop.
- **Phishing & Suspicious Indicators:** Detects unencrypted credential forms, cross-domain password submissions, punycode/homographs, hidden zero-sized iframes, and direct executable download links.
- **YARA Page Analysis:** Analyzes the downloaded HTML/JS payload through compiled YARA rules.

---

## 6. Scan Status Decision Matrix

| Status | Rule |
|---|---|
| **CLEAN** | All required security engines completed and verified 0 threats. |
| **SUSPICIOUS** | Heuristic rules or YARA rules identified risky behavior without confirmed malware signature. |
| **MALICIOUS** | A verified malware signature, ransomware pattern, or SSRF attempt was detected. |
| **ERROR** | An unexpected error occurred during processing. |
| **UNABLE_TO_SCAN** | The file or engine could not complete (e.g. password-encrypted archive or scanner offline). Files are **never** marked CLEAN if a scanner is unreachable. |

---

## 7. API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Application & database connectivity health |
| `GET` | `/api/health/scanners` | ClamAV daemon and YARA rule status |
| `POST` | `/api/scan/file` | Upload file (`multipart/form-data`) |
| `POST` | `/api/scan/zip` | Upload and inspect ZIP archive |
| `POST` | `/api/scan/url` | Inspect URL for threats and SSRF |
| `GET` | `/api/scan/{scan_id}` | Retrieve detailed scan report |
| `GET` | `/api/scan/{scan_id}/status` | Check current scan status |
| `GET` | `/api/scan/history` | Paginated scan history (`?page=1&limit=10`) |
| `GET` | `/api/scan/{scan_id}/report` | Download JSON or PDF report (`?format=pdf`) |

---

## 8. Postman Testing Guide

1. Open Postman.
2. Click **Import** and select `postman/FileScanner_Postman_Collection.json`.
3. Set Collection Variables:
   - `base_url`: `http://127.0.0.1:8000`
   - `scan_id`: (auto-populated by test scripts)
4. Execute the requests sequentially:
   - **Request 1 & 2:** Health checks.
   - **Request 3:** Upload a PDF.
   - **Request 5:** Upload an EICAR test string (`MALICIOUS`).
   - **Request 6:** Upload a ZIP archive.
   - **Request 7:** Scan a URL.
   - **Request 8 & 9:** Retrieve scan status and full results.
   - **Request 11:** Download PDF report.
   - **Request 15:** Test Localhost URL blocking (verifies SSRF protection).

---

## 9. Running Automated Tests

Run the complete test suite with verbose reporting:

```powershell
$env:PYTHONPATH="."
pytest -v
```

All 23 security, scanner, ZIP, and SSRF tests will run and validate against the backend.

