import os
import sys
import time
import signal
import subprocess
import threading
import requests
from typing import Optional, List

                                                                               
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "target_app"))

from tools.sast_scanner import scan_directory, format_findings
from tools.fuzzer import SQLiFuzzer, format_results as format_fuzz
from tools.dast_runner import DASTRunner, format_evidence
from agent.reasoner import reason
from agent.llm_client import get_active_provider
from agent.patch_agent import generate_and_apply_patch, restore_original, print_diff
from harness.security_replay import run_security_regression, format_security_report
from harness.regression_runner import run_regression, print_report

                                                                                
                
                                                                                

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[90m"

def header(text: str):
    width = 62
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * width}{RESET}")

def step(icon: str, text: str):
    ts = time.strftime("%H:%M:%S")
    print(f"  {DIM}{ts}{RESET}  {icon}  {text}")

def ok(text: str):   step(f"{GREEN}✓{RESET}", text)
def warn(text: str): step(f"{YELLOW}⚠{RESET}", text)
def err(text: str):  step(f"{RED}✗{RESET}", text)
def info(text: str): step(f"{CYAN}◉{RESET}", text)


                                                                                
                    
                                                                                

class AppServer:


    def __init__(self, app_dir: str, port: int):
        self.app_dir = app_dir
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        env = os.environ.copy()
                                                                                
        env["OVERWATCH_PORT"] = str(self.port)
        self._proc = subprocess.Popen(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0,'.'); "
             f"from database import init_db; init_db(); "
             f"from app import app; app.run(port={self.port}, debug=False)"],
            cwd=self.app_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        self._wait_ready()

    def _wait_ready(self, retries=30, delay=0.5):
        for _ in range(retries):
            try:
                r = requests.get(f"{self.base_url}/health", timeout=2)
                if r.status_code == 200:
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
        self.stop()
        time.sleep(0.5)
        self.start()


                                                                                
                   
                                                                                

MAX_ITERATIONS = 3
TARGET_APP_DIR = os.path.join(REPO_ROOT, "target_app")
TARGET_FILE    = os.path.join(TARGET_APP_DIR, "app.py")
FUZZ_PORT      = 5010
DAST_PORT      = 5011


def run():
    print(f"\n{BOLD}")
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║           CYBER OVERWATCH — Autonomous Analysis          ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

                                                                                
    header("PHASE 1 — Static Analysis (SAST)")
    info("Scanning target_app/ for SQL injection patterns …")
    sast_findings = scan_directory(TARGET_APP_DIR)
    sast_text = format_findings(sast_findings)
    print(sast_text)

    if not sast_findings:
        warn("SAST found no issues. Stopping — no targets for investigation.")
        return
    ok(f"{len(sast_findings)} suspicious location(s) found by SAST")

                                                                                
    header("PHASE 2 — Black-box Fuzzing")
    info("Starting target app on port 5010 …")
    fuzz_server = AppServer(TARGET_APP_DIR, FUZZ_PORT)
    fuzz_server.start()
    ok("Target app running")

    info(f"Firing SQLi payloads at {fuzz_server.base_url} …")
    fuzzer = SQLiFuzzer(fuzz_server.base_url)
    fuzz_results = fuzzer.fuzz_all()
    fuzz_text = format_fuzz(fuzz_results)
    print(fuzz_text)
    vulnerable_endpoints = [r for r in fuzz_results if r.vulnerable]
    ok(f"{len(vulnerable_endpoints)}/{len(fuzz_results)} endpoints confirmed vulnerable by fuzzer")
    fuzz_server.stop()

                                                   
    best_payload = None
    for r in fuzz_results:
        if r.best_payload:
            best_payload = r.best_payload
            break

                                                                                
    header("PHASE 3 — Dynamic Analysis (DAST)")
    info("Starting isolated DAST target on port 5011 …")
    dast_server = AppServer(TARGET_APP_DIR, DAST_PORT)
    dast_server.start()
    ok("DAST target running")

    info("Running runtime exploit probes …")
    dast_runner = DASTRunner(TARGET_APP_DIR, base_url=f"http://127.0.0.1:{DAST_PORT}")
    dast_runner._proc = dast_server._proc                            
    dast_evidences = dast_runner.run_all_probes()
    dast_text = format_evidence(dast_evidences)
    print(dast_text)
    confirmed_exploits = [e for e in dast_evidences if e.exploit_succeeded]
    ok(f"{len(confirmed_exploits)}/{len(dast_evidences)} exploits confirmed at runtime")
    dast_server.stop()

                                                                                
    header("PHASE 4 — LLM Evidence Correlation")
    provider, model = get_active_provider()
    info(f"Sending SAST + Fuzzer + DAST evidence to LLM reasoner [{provider}: {model}] …")

    with open(TARGET_FILE, "r") as f:
        source_snippet = f.read()

    verdict = reason(sast_text, fuzz_text, dast_text, source_snippet)

    print(f"\n  Vulnerability type  : {BOLD}{verdict.vuln_type}{RESET}")
    print(f"  Confidence          : {BOLD}{verdict.confidence}{RESET}")
    print(f"  Confirmed           : {BOLD}{GREEN if verdict.confirmed else RED}{verdict.confirmed}{RESET}")
    print(f"  Affected location   : {verdict.affected_file}:{verdict.affected_line}")
    print(f"\n  Reasoning:\n    {verdict.reasoning}")
    print(f"\n  Root cause:\n    {verdict.root_cause}")
    print(f"\n  Suggested fix:\n    {verdict.suggested_fix}")

    if not verdict.confirmed:
        if verdict.need_more_evidence:
            warn("LLM requests more evidence — insufficient confidence. Stopping.")
        else:
            ok("LLM: No vulnerability confirmed. Application appears clean.")
        return

    print(f"\n  {RED}{BOLD}⚡ VULNERABILITY CONFIRMED: {verdict.vuln_type} [{verdict.confidence} confidence]{RESET}")

                                                                                
    header("PHASE 5 — Pre-Patch Security Baseline")
    info("Starting app to verify exploit works BEFORE patching …")
    baseline_server = AppServer(TARGET_APP_DIR, FUZZ_PORT)
    baseline_server.start()

    info("Running security regression (pre-patch) …")
    pre_results = run_security_regression(f"http://127.0.0.1:{FUZZ_PORT}", "pre_patch")
    print(format_security_report(pre_results, "pre_patch"))
    pre_confirmed = sum(1 for r in pre_results if r.passed)
    baseline_server.stop()

    if pre_confirmed == 0:
        warn("No exploits reproduced in pre-patch baseline — aborting (nothing to fix).")
        return
    ok(f"{pre_confirmed}/{len(pre_results)} exploits confirmed in pre-patch baseline")

                                                                                
    verified = False
    for iteration in range(1, MAX_ITERATIONS + 1):
        header(f"PHASE 6 — Patch Generation (Iteration {iteration}/{MAX_ITERATIONS})")

        if iteration > 1:
            info("Restoring original source before re-patching …")
            restore_original(TARGET_FILE)

        info("Generating patch …")
        patch_result = generate_and_apply_patch(
            TARGET_FILE,
            verdict.root_cause,
            verdict.suggested_fix,
            iteration=iteration,
        )

        if not patch_result["success"]:
            err(f"Patch produced no changes (iteration {iteration}). Trying next.")
            continue

        ok(f"Patch applied via [{patch_result['strategy']}] strategy")
        print(f"\n  {BOLD}Diff:{RESET}")
        print_diff(patch_result["diff"])

                                                                                
        header(f"PHASE 7 — Security Replay (Iteration {iteration})")
        info("Starting patched app …")
        patched_server = AppServer(TARGET_APP_DIR, FUZZ_PORT)
        patched_server.start()

        info("Replaying original exploits against patched app …")
        post_results = run_security_regression(f"http://127.0.0.1:{FUZZ_PORT}", "post_patch")
        print(format_security_report(post_results, "post_patch"))
        security_passed = all(r.passed for r in post_results)

                                                                                
        header(f"PHASE 8 — Functional Regression (Iteration {iteration})")
        info("Running pytest functional test suite …")
        report = run_regression(REPO_ROOT)
        print_report(report)
        functional_passed = report.all_passed

        patched_server.stop()

        if security_passed and functional_passed:
            verified = True
            break
        else:
            if not security_passed:
                err(f"Exploit still works after patch (iteration {iteration}).")
                                                                           
                fail_evidence = "\n".join(
                    f"{r.test_id}: {r.status}" for r in post_results if not r.passed
                )
                info(f"Evidence for re-patch: {fail_evidence}")
            if not functional_passed:
                err(f"Functional regression failed (iteration {iteration}).")
            if iteration < MAX_ITERATIONS:
                info(f"Retrying patch (iteration {iteration + 1}) …")

                                                                                
    print(f"\n{BOLD}")
    print("  ╔══════════════════════════════════════════════════════════╗")
    if verified:
        print(f"  ║  {GREEN}🛡️  VERIFIED FIX — ALL CHECKS PASSED{RESET}{BOLD}                   ║")
    else:
        print(f"  ║  {RED}❌  REMEDIATION FAILED — MANUAL REVIEW REQUIRED{RESET}{BOLD}         ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

    if verified:
        print(f"  {GREEN}Security regression : ALL EXPLOITS BLOCKED ✓{RESET}")
        print(f"  {GREEN}Functional tests    : {report.passed}/{report.total} PASSED ✓{RESET}")
        print(f"  {GREEN}Patch strategy      : {patch_result['strategy']}{RESET}")
    else:
        print(f"  {RED}Could not produce a verified fix in {MAX_ITERATIONS} iterations.{RESET}")
        print(f"  {YELLOW}Review the patch diff and regression results above.{RESET}")

    return verified


if __name__ == "__main__":
    run()
