import os
import sys
import time
import signal
import subprocess
import threading
import requests
from typing import Optional, List

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "real_target_adapter"))

from tools.sast_scanner    import scan_file, format_findings
from tools.fuzzer          import SQLiFuzzer, format_results as fmt_fuzz
from tools.dast_runner     import DASTRunner, format_evidence
from agent.reasoner        import reason
from agent.llm_client      import get_active_provider
from agent.patch_agent     import generate_and_apply_patch, restore_original, print_diff
from harness.regression_runner import run_regression, print_report

                                                                                
        
                                                                                

REAL_APP_DIR  = os.path.join(REPO_ROOT, "real_target_adapter")
REAL_APP_FILE = os.path.join(REAL_APP_DIR, "app.py")
FUZZ_PORT     = 5020
DAST_PORT     = 5021
MAX_ITER      = 3

                                                                                
                
                                                                                

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[90m"

def header(t):
    w = 66
    print(f"\n{BOLD}{CYAN}{'─'*w}{RESET}\n{BOLD}{CYAN}  {t}{RESET}\n{BOLD}{CYAN}{'─'*w}{RESET}")

def step(icon, t):
    ts = time.strftime("%H:%M:%S")
    print(f"  {DIM}{ts}{RESET}  {icon}  {t}")

def ok(t):   step(f"{GREEN}✓{RESET}", t)
def warn(t): step(f"{YELLOW}⚠{RESET}", t)
def err(t):  step(f"{RED}✗{RESET}", t)
def info(t): step(f"{CYAN}◉{RESET}", t)


                                                                                
            
                                                                                

class AppServer:
    def __init__(self, app_dir: str, port: int):
        self.app_dir  = app_dir
        self.port     = port
        self.base_url = f"http://127.0.0.1:{port}"
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        self._proc = subprocess.Popen(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0,'.'); "
             f"from app import init_db, app; init_db(); app.run(port={self.port}, debug=False)"],
            cwd=self.app_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait_ready()

    def _wait_ready(self, retries=30, delay=0.4):
        for _ in range(retries):
            try:
                if requests.get(f"{self.base_url}/health", timeout=2).status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(delay)
        raise RuntimeError(f"App never became ready at {self.base_url}")

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def restart(self):
        self.stop(); time.sleep(0.5); self.start()


                                                                                
                                         
                                                                                

REAL_SEC_TESTS = [
                                                      
    ("RBF-SQL-001", "Tautology bypass on /listservices category param",
     "GET", "/listservices", {"category": "products' OR '1'='1"}),
    ("RBF-SQL-002", "UNION dump of secret_stuff table via /listservices",
     "GET", "/listservices",
     {"category": "x' UNION SELECT name,description,category,description FROM secret_stuff--"}),
    ("RBF-SQL-003", "Single-quote crash / error disclosure",
     "GET", "/listservices", {"category": "x'"}),
    ("RBF-SQL-004", "Tautology on /api/item id parameter",
     "GET", "/api/item", {"id": "1 OR 1=1"}),
    ("RBF-SQL-005", "UNION dump via /api/item",
     "GET", "/api/item",
     {"id": "0 UNION SELECT name,description,name,description FROM secret_stuff--"}),
    ("RBF-SQL-006", "f-string injection via /api/search",
     "GET", "/api/search", {"q": "' OR '1'='1"}),
]

LEAK_SIGS   = ["none of these things", "single regex", "secret three", "secret_stuff"]
ERROR_SIGS  = ["operationalerror", "sqlite", "syntax error", "unrecognized token", "near \""]


def _vuln(resp: requests.Response) -> tuple:

    body = resp.text.lower()
    if resp.status_code == 500:
        for s in ERROR_SIGS:
            if s in body:
                return True, f"DB_ERROR: '{s}'"
    if resp.status_code == 200:
        for s in LEAK_SIGS:
            if s in body:
                return True, f"DATA_LEAK: '{s}' in response"
                                                                         
        try:
            data = resp.json()
            if isinstance(data, list) and len(data) >= 5:
                return True, f"TAUTOLOGY: returned {len(data)} rows (all)"
        except Exception:
            pass
    return False, ""


def run_security_suite(base_url: str, phase: str) -> list:
    results = []
    for tid, desc, method, endpoint, params in REAL_SEC_TESTS:
        url = base_url + endpoint
        try:
            resp = requests.get(url, params=params, timeout=5)
            vulnerable, reason_str = _vuln(resp)
        except Exception as e:
            vulnerable, reason_str = False, str(e)
            resp = type("R", (), {"status_code": 0})()

        if phase == "pre_patch":
            passed = vulnerable
            status = "VULNERABLE" if vulnerable else "BLOCKED"
            expected = "VULNERABLE"
        else:
            passed = not vulnerable
            status = "BLOCKED" if not vulnerable else "VULNERABLE"
            expected = "BLOCKED"

        results.append({
            "tid": tid, "desc": desc, "passed": passed,
            "status": status, "expected": expected,
            "http": resp.status_code, "reason": reason_str,
        })
    return results


def print_security_results(results: list, phase: str):
    print(f"\n  ── Security Regression ({phase.replace('_',' ').title()}) ──")
    p = sum(1 for r in results if r["passed"])
    for r in results:
        icon = f"{GREEN}✓{RESET}" if r["passed"] else f"{RED}✗{RESET}"
        print(f"  {icon}  {r['tid']:<14} {r['status']:<12} HTTP {r['http']}  {r['reason']}")
    print(f"\n  Result: {p}/{len(results)} passed")


                                                                                
                  
                                                                                

def run():
    print(f"\n{BOLD}")
    print("  ╔════════════════════════════════════════════════════════════════╗")
    print("  ║    CYBER OVERWATCH — Real-World Target Attack                  ║")
    print("  ║    Source: stephenbradshaw/breakableflask (MIT)                ║")
    print("  ╚════════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

                                                                                 
    header("PHASE 1 — SAST Scan of real_target_adapter/app.py")
    info("Running AST-based scanner on open-source vulnerable code …")
    sast_findings = scan_file(REAL_APP_FILE)
    sast_text = format_findings(sast_findings)
    print(sast_text)
    ok(f"{len(sast_findings)} findings from SAST")

                                                                                 
    header("PHASE 2 — Black-box Fuzzing")
    info(f"Starting real target on port {FUZZ_PORT} …")
    fuzz_server = AppServer(REAL_APP_DIR, FUZZ_PORT)
    fuzz_server.start()
    ok("Real target app running")

    info("Firing SQLi payload library …")
    fuzzer = SQLiFuzzer(fuzz_server.base_url)
                                          
    fuzz_results = [
        fuzzer.fuzz_get("/listservices", "category", safe_value="products"),
        fuzzer.fuzz_get("/api/item",     "id",       safe_value="1"),
        fuzzer.fuzz_get("/api/search",   "q",        safe_value="Military"),
    ]
    fuzz_text = fmt_fuzz(fuzz_results)
    print(fuzz_text)
    vuln_eps = [r for r in fuzz_results if r.vulnerable]
    ok(f"{len(vuln_eps)}/{len(fuzz_results)} endpoints vulnerable")
    fuzz_server.stop()

                                                                                 
    header("PHASE 3 — Dynamic Analysis (DAST)")
    info(f"Starting DAST target on port {DAST_PORT} …")
    dast_server = AppServer(REAL_APP_DIR, DAST_PORT)
    dast_server.start()

    info("Running runtime exploit probes …")
    dast_evidences = []
    probe_targets = [
        ("/listservices", {"category": "products' OR '1'='1"}),
        ("/listservices", {"category": "x' UNION SELECT name,description,category,description FROM secret_stuff--"}),
        ("/api/item",     {"id": "1 OR 1=1"}),
        ("/api/search",   {"q": "' OR '1'='1"}),
    ]
    for endpoint, params in probe_targets:
        try:
            resp = requests.get(f"http://127.0.0.1:{DAST_PORT}{endpoint}", params=params, timeout=5)
            vul, rsn = _vuln(resp)
            dast_evidences.append({
                "endpoint": endpoint,
                "params": params,
                "exploit_succeeded": vul,
                "reason": rsn,
                "http": resp.status_code,
                "snippet": resp.text[:200].replace("\n", " "),
            })
        except Exception as e:
            dast_evidences.append({"endpoint": endpoint, "exploit_succeeded": False, "reason": str(e)})

    for e in dast_evidences:
        icon = f"{RED}🔴 CONFIRMED{RESET}" if e["exploit_succeeded"] else f"{GREEN}🟢 clean{RESET}"
        print(f"  {icon}  {e['endpoint']}  →  {e.get('reason','')}")
    confirmed_dast = sum(1 for e in dast_evidences if e["exploit_succeeded"])
    ok(f"{confirmed_dast}/{len(dast_evidences)} exploits confirmed at runtime")
    dast_server.stop()

    dast_text = "\n".join(
        f"{'CONFIRMED' if e['exploit_succeeded'] else 'clean'}: {e['endpoint']} — {e.get('reason','')}"
        for e in dast_evidences
    )

                                                                                
    header("PHASE 4 — LLM Evidence Correlation")
    provider, model = get_active_provider()
    info(f"Correlating SAST + Fuzzer + DAST evidence [{provider}: {model}] …")
    with open(REAL_APP_FILE) as f:
        source = f.read()

    verdict = reason(sast_text, fuzz_text, dast_text, source)

    print(f"\n  Vulnerability type  : {BOLD}{verdict.vuln_type}{RESET}")
    print(f"  Confidence          : {BOLD}{verdict.confidence}{RESET}")
    print(f"  Confirmed           : {BOLD}{GREEN if verdict.confirmed else RED}{verdict.confirmed}{RESET}")
    print(f"\n  Reasoning:\n    {verdict.reasoning}")
    print(f"\n  Root cause:\n    {verdict.root_cause}")
    print(f"\n  Suggested fix:\n    {verdict.suggested_fix}")

    if not verdict.confirmed:
        warn("LLM: No vulnerability confirmed. Stopping.")
        return False

    print(f"\n  {RED}{BOLD}⚡ VULNERABILITY CONFIRMED: {verdict.vuln_type} [{verdict.confidence}]{RESET}")

                                                                                 
    header("PHASE 5 — Pre-Patch Security Baseline")
    info("Confirming exploits reproduce BEFORE patch …")
    pre_server = AppServer(REAL_APP_DIR, FUZZ_PORT)
    pre_server.start()
    pre_results = run_security_suite(f"http://127.0.0.1:{FUZZ_PORT}", "pre_patch")
    print_security_results(pre_results, "pre_patch")
    pre_ok = sum(1 for r in pre_results if r["passed"])
    pre_server.stop()

    if pre_ok == 0:
        warn("No exploits reproduced in baseline — nothing to fix.")
        return False
    ok(f"{pre_ok}/{len(pre_results)} exploits confirmed pre-patch")

                                                                                 
    verified = False
    report = None

    for iteration in range(1, MAX_ITER + 1):
        header(f"PHASE 6 — Patch Generation (Iteration {iteration}/{MAX_ITER})")

        if iteration > 1:
            info("Restoring original source …")
            restore_original(REAL_APP_FILE)

        info("Generating parameterized-query patch for real-world SQLi …")
        patch_result = generate_and_apply_patch(
            REAL_APP_FILE,
            verdict.root_cause,
            verdict.suggested_fix,
            iteration=iteration,
        )

        if not patch_result["success"]:
            err(f"Patch produced no changes (iteration {iteration}).")
            continue

        ok(f"Patch applied via [{patch_result['strategy']}] strategy")
        print(f"\n  {BOLD}Patch Diff (real breakableflask vulnerability):{RESET}")
        print_diff(patch_result["diff"])

                                                                                 
        header(f"PHASE 7 — Security Replay (Iteration {iteration})")
        info("Starting patched app …")
        patched_server = AppServer(REAL_APP_DIR, FUZZ_PORT)
        patched_server.start()

        info("Replaying all original exploits …")
        post_results = run_security_suite(f"http://127.0.0.1:{FUZZ_PORT}", "post_patch")
        print_security_results(post_results, "post_patch")
        security_ok = all(r["passed"] for r in post_results)

                                                                                
        header(f"PHASE 8 — Functional Regression (Iteration {iteration})")
        info("Running pytest functional test suite …")
        report = run_regression(
            REPO_ROOT,
            test_file="harness/test_real_target.py",
            extra_pythonpath=REAL_APP_DIR,
        )
        print_report(report)
        functional_ok = report.all_passed

        patched_server.stop()

        if security_ok and functional_ok:
            verified = True
            break
        else:
            if not security_ok:
                err(f"Exploit still works (iteration {iteration}).")
            if not functional_ok:
                err(f"Functional regression failed (iteration {iteration}).")
            if iteration < MAX_ITER:
                info(f"Retrying patch (iteration {iteration + 1}) …")

                                                                                 
    print(f"\n{BOLD}")
    print("  ╔════════════════════════════════════════════════════════════════╗")
    if verified:
        print(f"  ║  {GREEN}🛡️  VERIFIED FIX — breakableflask SQLi PATCHED{RESET}{BOLD}              ║")
    else:
        print(f"  ║  {RED}❌  REMEDIATION FAILED — MANUAL REVIEW REQUIRED{RESET}{BOLD}             ║")
    print("  ╚════════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

    if verified and report:
        print(f"  {GREEN}Source            : stephenbradshaw/breakableflask (real open-source){RESET}")
        print(f"  {GREEN}Security tests    : ALL EXPLOITS BLOCKED ✓{RESET}")
        print(f"  {GREEN}Functional tests  : {report.passed}/{report.total} PASSED ✓{RESET}")
        print(f"  {GREEN}Patch strategy    : {patch_result['strategy']}{RESET}")

    return verified


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
