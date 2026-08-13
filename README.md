# Cyber Overwatch — Autonomous Vulnerability Discovery, Patch & Verification

An autonomous cyber-reasoning system that **finds a SQL injection vulnerability, patches it, and proves the fix holds** — without human intervention.

## What It Does

```
VULNERABLE CODE
      ↓
SAST Scan (AST-based)
      ↓
LLM Reasoner (correlates evidence)
      ↓
Fuzzer (black-box SQLi payloads)
      ↓
DAST (runtime exploit probes)
      ↓
VULNERABILITY CONFIRMED
      ↓
LLM Patch Agent
      ↓
SAME EXPLOIT REPLAYED → BLOCKED ✓
      ↓
18/18 REGRESSION TESTS PASS ✓
      ↓
🛡️ VERIFIED FIX
```

## Quickstart

```bash
pip install -r requirements.txt
python run.py
```

Set `GOOGLE_API_KEY` for Gemini-powered reasoning (optional — falls back to rule-based mock).

## Project Structure

```
cyber_overwatch/
├── target_app/           # Deliberately vulnerable Flask app (SQL injection x3)
│   ├── app.py            # 3 vulnerable endpoints
│   └── database.py       # SQLite with seed users
├── tools/
│   ├── sast_scanner.py   # Pure-Python AST scanner (zero deps)
│   ├── fuzzer.py         # HTTP fuzzer (20 SQLi payloads)
│   └── dast_runner.py    # Runtime exploit confirmation
├── agent/
│   ├── reasoner.py       # LLM evidence correlator (Gemini / mock)
│   ├── patch_agent.py    # LLM patch generator + unified diff
│   └── orchestrator.py   # Master autonomous loop (8 phases)
├── harness/
│   ├── security_replay.py    # 5 permanent security test cases (SEC-SQL-001…005)
│   ├── regression_runner.py  # pytest wrapper with JSON reporting
│   └── test_target_app.py    # 18 functional + security regression tests
└── run.py                # Entry point
```

## The 8-Phase Autonomous Loop

| Phase | What happens |
|---|---|
| 1 SAST | AST scan finds 3 injection sites |
| 2 Fuzzer | 20 payloads, detects data leak / DB error / 500 |
| 3 DAST | Runtime probes confirm taint flow |
| 4 LLM | Correlates 3 sources → HIGH confidence SQLi |
| 5 Baseline | Confirms exploits work BEFORE patch |
| 6 Patch | Generates & applies parameterized-query fix |
| 7 Security replay | Same exploits → all BLOCKED |
| 8 Regression | 18/18 functional tests → all PASS |

## Sample Output

```
  ⚡ VULNERABILITY CONFIRMED: SQL_INJECTION [HIGH confidence]

  Diff:
  - query = "SELECT ... WHERE id = " + user_id
  + query = "SELECT ... WHERE id = ?"
  - rows = conn.execute(query).fetchall()
  + rows = conn.execute(query, (user_id,)).fetchall()

  Security Regression (post_patch):
  ✓  SEC-SQL-001    BLOCKED    HTTP 200
  ✓  SEC-SQL-002    BLOCKED    HTTP 200
  ✓  SEC-SQL-003    BLOCKED    HTTP 401
  ✓  SEC-SQL-004    BLOCKED    HTTP 401
  ✓  SEC-SQL-005    BLOCKED    HTTP 200

  Functional Regression:
  ✓ 18/18 tests passed

  ╔══════════════════════════════════════════════════════════╗
  ║  🛡️  VERIFIED FIX — ALL CHECKS PASSED                   ║
  ╚══════════════════════════════════════════════════════════╝
```

## Security Test Cases (Permanent Harness)

| ID | Description | Pre-patch | Post-patch |
|---|---|---|---|
| SEC-SQL-001 | OR 1=1 tautology (GET /api/user) | VULNERABLE | BLOCKED |
| SEC-SQL-002 | UNION data dump (GET /api/user) | VULNERABLE | BLOCKED |
| SEC-SQL-003 | Auth bypass admin'-- (POST /api/login) | VULNERABLE | BLOCKED |
| SEC-SQL-004 | OR tautology auth bypass | VULNERABLE | BLOCKED |
| SEC-SQL-005 | Search injection | VULNERABLE | BLOCKED |

## Key Design Decisions

- **LLM reasons over real evidence** — not hallucinating; it receives SAST text + fuzz results + DAST probes
- **Iterative loop** — if patch fails, agent gets failure evidence and retries (up to 3 rounds)
- **Zero external SAST deps** — pure Python `ast` module, works anywhere
- **Mock fallback** — runs fully offline without Gemini key using deterministic rule-based reasoning