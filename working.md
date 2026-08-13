# Technical Architecture & Blueprint: Autonomous Cyber Regression Test Harness

## Executive Summary & Core Objective

The **Autonomous Cyber Regression Test Harness** is an agentic cyber-defense system designed to find software vulnerabilities, generate targeted patches, and rigorously verify remediations without human intervention.

Rather than relying on unverified LLM assertions, the harness requires **multi-modal independent proof** across static, fuzzing, and dynamic execution layers before classifying any flaw as confirmed. Once confirmed, the system autonomously derives the root cause, applies a minimal diff-based patch in an isolated environment, and proves via a dual regression suite that:
1. **The security exploit is permanently blocked** (Security Regression Replay).
2. **The application's functional requirements remain 100% intact** (Functional Pytest Suite).

---

## Autonomous 8-Phase Lifecycle

```mermaid
flowchart TD
    A[Vulnerable Source Code] --> B[Phase 1: Multi-Pass AST SAST Scan]
    B --> C[Phase 2: Black-Box HTTP Fuzzing]
    C --> D[Phase 3: DAST Runtime Taint Probing]
    D --> E[Phase 4: Multi-Modal LLM Evidence Correlation]
    E -->|Confirmed Vulnerability| F[Phase 5: Pre-Patch Security Baseline]
    F --> G[Phase 6: AST-Aware Minimal Patch Generation]
    G --> H[Phase 7: Security Replay Regression Test]
    H -->|Exploits Blocked| I[Phase 8: Functional Regression Pytest Suite]
    I -->|100% Pass| J[🛡️ Verified Autonomous Remediated Code]
    H -->|Exploit Succeeded| K[Retry Patch Generation (Iteration 2/3)]
    I -->|Functional Failure| K
    K --> G
```

---

## Deep Dive: Phase-by-Phase Technical Mechanics

### Phase 1: Static Application Security Testing (SAST)
* **File:** `tools/sast_scanner.py`
* **Technology:** Python `ast` (Abstract Syntax Tree), Standard Library
* **Methodology:** 
  * Uses a two-pass AST visitor pattern.
  * **Pass 1 (Function-Scoped Assignment Mapping):** Traverses `ast.Assign` and `ast.AnnAssign` nodes per function scope (`_var_scopes`) to track local variable assignments and prevent cross-function name shadowing.
  * **Pass 2 (Taint & Call Analysis):** Intercepts execution calls (`execute`, `executemany`, `executescript`). Resolves passed arguments back to their source expressions via `_resolve_in_context`.
  * Flags vulnerable patterns:
    * `SQLI-CONCAT`: Binary addition (`+`) joining SQL string literals with dynamic variables.
    * `SQLI-FSTRING`: `ast.JoinedStr` interpolation inside SQL strings.
    * `SQLI-FORMAT-METHOD`: `.format()` call on strings matching SQL keywords (`SELECT`, `WHERE`, `INSERT`, `UPDATE`, `DELETE`).
    * `SQLI-PERCENT-FORMAT`: `%` formatting on SQL strings.

### Phase 2: Black-Box HTTP Fuzzing
* **File:** `tools/fuzzer.py`
* **Technology:** Python `requests`, HTTP anomaly detection
* **Methodology:**
  * Discovers endpoints and injects a specialized dictionary of 20+ SQLi payloads across GET parameters, query strings, and JSON request bodies.
  * Payloads include: Tautologies (`' OR '1'='1`), UNION select dumps (`' UNION SELECT...`), comments (`'--`, `/*`), error-triggering single quotes (`'`).
  * Evaluates responses against anomaly criteria:
    * `STATUS_500`: Unhandled internal database driver exceptions.
    * DB Error Signatures: Matching SQLite/Postgres error text (`syntax error`, `unrecognized token`, `operationalerror`).
    * Data Leakage: Unexpected exposure of sensitive table strings (`alice`, `admin`, `secret_stuff`).

### Phase 3: Dynamic Application Security Testing (DAST)
* **File:** `tools/dast_runner.py`
* **Technology:** Runtime taint tracking, payload execution probing
* **Methodology:**
  * Executes targeted runtime probes against active Flask application instances.
  * Probes specifically verify taint propagation from HTTP entry points to the database query response.
  * Categorizes evidence into explicit runtime proof indicators (`TAUTOLOGY_DUMP`, `DATA_LEAKAGE`, `SYNTAX_DISCLOSURE`).

### Phase 4: Multi-Modal LLM Evidence Correlation
* **File:** `agent/reasoner.py`
* **Technology:** Google Gemini 1.5 Flash (API) / Rule-based Deterministic Fallback Engine
* **Methodology:**
  * Aggregates raw outputs from SAST, Fuzzer, and DAST phases into a unified evidence vector.
  * Enforces strict multi-factor verification rules: an LLM recommendation alone can **NEVER** declare a vulnerability confirmed. Confirmation requires matching static AST signals and dynamic runtime proof.
  * Produces structured diagnostic metadata:
    * `vuln_type`: Standardized classification (e.g., `SQL_INJECTION`).
    * `confidence`: `HIGH` (3/3 layers match) or `MEDIUM` (2/3 layers match).
    * `root_cause`: Detailed flow analysis explaining where parameterization was omitted.
    * `suggested_fix`: Precise parameterization strategy using driver placeholders (`?`).

### Phase 5: Pre-Patch Security Baseline
* **Files:** `harness/security_replay.py`, `agent/orchestrator.py`
* **Technology:** Execution harness, baseline recorder
* **Methodology:**
  * Runs the full suite of permanent security exploit cases against the active unpatched target application.
  * Establishes a verifiable baseline confirming that the target is indeed exploit-vulnerable prior to applying any code modification.

### Phase 6: Autonomous Minimal Patch Generation
* **File:** `agent/patch_agent.py`
* **Technology:** LLM Code Transformation / Precise Unified Diff Engine
* **Methodology:**
  * Generates parameterized query replacements for insecure string formatting:
    * Replaces string concatenation `query = "SELECT ... WHERE id = " + user_id` with parameterized tuples `query = "SELECT ... WHERE id = ?"`, passing `(user_id,)` to `cursor.execute()`.
    * Replaces `.format(...)` and f-strings with SQL parameter placeholders.
  * Generates clean Git-style unified diffs (`_make_diff`) detailing exact line-by-line additions and deletions.
  * Backs up original target files (`app.py.original`) to enable instant rollback if verification fails.

### Phase 7: Security Replay Regression Testing
* **File:** `harness/security_replay.py`
* **Technology:** Automated exploit replay engine
* **Methodology:**
  * Spawns the newly patched application instance on an isolated port.
  * Replays every payload from the original attack suite.
  * Verifies that previously successful exploits now return safe HTTP responses (e.g., HTTP 200 with empty/filtered lists or HTTP 401 for unauthorized access) and produce zero DB errors.

### Phase 8: Functional Regression Testing
* **Files:** `harness/regression_runner.py`, `harness/test_target_app.py`, `harness/test_real_target.py`
* **Technology:** `pytest`, programmatic JSON report parsing
* **Methodology:**
  * Runs comprehensive functional `pytest` suites against the patched application.
  * Verifies normal application operations (e.g., healthy status endpoints, valid user lookups, legitimate credential authentication, standard search queries).
  * Enforces 100% pass criteria (`passed == total`). If any functional test breaks or any exploit bypasses the patch, the orchestrator triggers an iterative re-patch loop (up to 3 iterations).

---

## Comparative Target Evaluation

The harness has been tested and verified across two distinct applications:

| Characteristic | Synthetic Target (`target_app/`) | Real Open-Source Target (`real_target_adapter/`) |
|---|---|---|
| **Origin** | Custom test app | `stephenbradshaw/breakableflask` (GitHub open-source) |
| **Vulnerability Types** | Concatenation SQLi, f-string SQLi, LIKE clause SQLi | `.format()` WHERE clause injection, item ID `.format()` SQLi, f-string LIKE SQLi |
| **SAST Findings** | 9 findings | 9 findings |
| **Fuzzer Anomaly Detections** | 3 endpoints flagged | 3 endpoints flagged |
| **DAST Exploits Confirmed** | 2/5 probes confirmed | 3/4 probes confirmed |
| **Patch Strategy** | Parameterized `?` tuples | Parameterized conditional query structure |
| **Security Replay** | 5/5 exploits blocked | 6/6 exploits blocked |
| **Functional Tests** | 18/18 pytest cases pass | 16/16 pytest cases pass |

---

## File System & Repository Organization

```
Beyond-Sandbox/
├── working.md                   # Complete architectural reference & documentation
├── README.md                    # Project quickstart & overview
├── requirements.txt             # Core dependencies (Flask, requests, pytest)
├── run.py                       # Main launcher for synthetic target pipeline
├── attack_real.py               # Main launcher for real-world breakableflask pipeline
├── .gitignore                   # Git exclusion rules for databases and caches
│
├── agent/                       # Autonomous Reasoning & Execution Layer
│   ├── __init__.py
│   ├── orchestrator.py          # Master 8-phase pipeline orchestrator
│   ├── patch_agent.py           # Patch generation, template fallback & diff engine
│   └── reasoner.py              # Multi-modal evidence correlator (Gemini / Mock)
│
├── tools/                       # Multi-Modal Inspection Tools
│   ├── __init__.py
│   ├── sast_scanner.py          # Pure Python 2-pass AST static analysis scanner
│   ├── fuzzer.py                # Black-box HTTP fuzzer & payload library
│   └── dast_runner.py           # Dynamic runtime exploit prober
│
├── harness/                     # Verification & Regression Layer
│   ├── __init__.py
│   ├── security_replay.py       # Permanent security exploit replay test suite
│   ├── regression_runner.py     # Pytest execution wrapper & JSON parser
│   ├── test_target_app.py       # Functional regression suite for synthetic target
│   └── test_real_target.py      # Functional regression suite for breakableflask target
│
├── target_app/                  # Baseline Synthetic Vulnerable Target
│   ├── app.py                   # Vulnerable Flask app (3 SQLi endpoints)
│   ├── database.py              # SQLite database initialization & seeding
│   └── requirements.txt
│
└── real_target_adapter/         # Real-World Open-Source Vulnerable Target
    ├── app.py                   # Adapted breakableflask Flask app (SQLi vulnerabilities)
    └── breakdb.sqlite           # SQLite database instance
```

---

## Execution Commands

### 1. Run Synthetic Target Pipeline
```bash
python run.py
```

### 2. Run Real-World Open-Source Target Pipeline (`breakableflask`)
```bash
python attack_real.py
```

### 3. Run Standalone SAST Scanner
```bash
python tools/sast_scanner.py target_app
```

### 4. Run Pytest Functional Suites Directly
```bash
pytest harness/test_target_app.py
pytest harness/test_real_target.py
```
