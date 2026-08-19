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

                                                                                
    history = []
    verified = False
    patch_result = None

    for iteration in range(1, MAX_ITERATIONS + 1):
        header(f"PHASE 6 — Patch Generation (Iteration {iteration}/{MAX_ITERATIONS})")

        # Always make sure the original source is clean at the start of the iteration
        info("Restoring original source for clean patch generation …")
        restore_original(TARGET_FILE)

        info("[PATCH] Vulnerability: SQL_INJECTION")
        info(f"[PATCH] Target: {TARGET_FILE}:{verdict.affected_line}")
        info("Generating candidate patch...")
        
        patch_result = generate_and_apply_patch(
            TARGET_FILE,
            verdict.root_cause,
            verdict.suggested_fix,
            iteration=iteration,
            sast_text=sast_text,
            fuzz_text=fuzz_text,
            dast_text=dast_text,
            verdict=verdict,
            history=history,
        )

        syntax_ok = patch_result.get("syntax_valid", False)
        print(f"  [PATCH] Syntax validation: {'PASS' if syntax_ok else 'FAIL'}")

        if not patch_result["success"]:
            err(f"Patch generation/application failed (iteration {iteration}).")
            # Log failure in history
            history.append({
                "iteration": iteration,
                "strategy": patch_result.get("strategy", "unknown"),
                "diff": "",
                "syntax_valid": syntax_ok,
                "security_details": "Failed to generate a valid/syntax-passing candidate.",
                "functional_details": "",
            })
            # Make sure we clean up the file
            restore_original(TARGET_FILE)
            continue

        ok(f"Temporary patch applied via [{patch_result['strategy']}] strategy")
        print(f"\n  {BOLD}Diff:{RESET}")
        print_diff(patch_result["diff"])

        header(f"PHASE 7 — Security Replay (Iteration {iteration})")
        info("Starting patched app …")
        
        security_passed = False
        functional_passed = False
        post_results = []
        report = None

        try:
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
        except Exception as e:
            err(f"Error during patch verification: {e}")
            if 'patched_server' in locals():
                try: patched_server.stop()
                except: pass

        if security_passed and functional_passed:
            verified = True
            ok("All checks passed! Patch verified successfully.")
            break
        else:
            # Revert the patch immediately to maintain target safety
            info("Verification failed. Reverting temporary patch and recording failure context …")
            restore_original(TARGET_FILE)

            # Record failure context
            sec_fail_desc = ""
            if not security_passed:
                err(f"[PATCH] Security verification: FAIL")
                sec_fail_desc = "\n".join(
                    f"{r.test_id}: {r.status} (HTTP {r.http_code})" for r in post_results if not r.passed
                )
                print(f"  [PATCH] Reason: Exploit payloads still succeed:\n{sec_fail_desc}")
            else:
                ok(f"[PATCH] Security verification: PASS")

            func_fail_desc = ""
            if not functional_passed:
                err(f"[PATCH] Regression verification: FAIL")
                if report and report.tests:
                    func_fail_desc = "\n".join(
                        f"{t.test_id}: {t.outcome} - {t.message.strip()}" for t in report.tests if t.outcome != "passed"
                    )
                else:
                    func_fail_desc = "Functional tests failed to execute properly."
                print(f"  [PATCH] Reason: Functional regressions failed:\n{func_fail_desc}")
            else:
                ok(f"[PATCH] Regression verification: PASS")

            history.append({
                "iteration": iteration,
                "strategy": patch_result.get("strategy", "unknown"),
                "diff": patch_result.get("diff", ""),
                "syntax_valid": syntax_ok,
                "security_details": sec_fail_desc,
                "functional_details": func_fail_desc,
            })

            if iteration < MAX_ITERATIONS:
                info(f"Generating repair attempt {iteration + 1} …")

    # If LLM failed, try deterministic template fallback as a final option (Step 11)
    if not verified:
        header("FINAL FALLBACK — Applying Deterministic Template Patch")
        restore_original(TARGET_FILE)
        
        info("Applying deterministic template patch …")
        with open(TARGET_FILE, "r", encoding="utf-8") as fh:
            source = fh.read()
        
        # Determine if it's the real target or regular target
        is_real_target = "real_target_adapter" in TARGET_FILE
        if is_real_target:
            from agent.patch_agent import _apply_real_target_patch
            patched_source = _apply_real_target_patch(source)
            strategy = "real_target_template"
        else:
            from agent.patch_agent import _apply_template_patch
            patched_source = _apply_template_patch(source)
            strategy = "template"
            
        with open(TARGET_FILE, "w", encoding="utf-8") as fh:
            fh.write(patched_source)
            
        # Verify the deterministic fallback
        info("Verifying deterministic fallback patch …")
        security_passed = False
        functional_passed = False
        
        try:
            fallback_server = AppServer(TARGET_APP_DIR, FUZZ_PORT)
            fallback_server.start()
            
            post_results = run_security_regression(f"http://127.0.0.1:{FUZZ_PORT}", "post_patch")
            security_passed = all(r.passed for r in post_results)
            
            report = run_regression(REPO_ROOT)
            functional_passed = report.all_passed
            
            fallback_server.stop()
        except Exception as e:
            err(f"Fallback verification failed: {e}")
            if 'fallback_server' in locals():
                try: fallback_server.stop()
                except: pass
                
        if security_passed and functional_passed:
            verified = True
            ok("Deterministic fallback patch verified successfully!")
            # Generate dummy patch result for reporting
            from agent.patch_agent import _make_diff
            diff_text = _make_diff(source, patched_source, os.path.basename(TARGET_FILE))
            patch_result = {
                "strategy": strategy,
                "diff": diff_text,
            }
        else:
            err("Deterministic fallback also failed verification! Reverting target file to pristine state.")
            restore_original(TARGET_FILE)

    print(f"\n{BOLD}")
    print("  ╔══════════════════════════════════════════════════════════╗")
    if verified:
        print(f"  ║  {GREEN}🛡️  VERIFIED FIX — ALL CHECKS PASSED{RESET}{BOLD}                   ║")
        print(f"  ║  [PATCH] FINAL STATUS: VERIFIED                          ║")
    else:
        print(f"  ║  {RED}❌  REMEDIATION FAILED — MANUAL REVIEW REQUIRED{RESET}{BOLD}         ║")
        print(f"  ║  [PATCH] FINAL STATUS: FAILED                            ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

    if verified:
        print(f"  {GREEN}Security regression : ALL EXPLOITS BLOCKED ✓{RESET}")
        print(f"  {GREEN}Functional tests    : {report.passed}/{report.total} PASSED ✓{RESET}")
        print(f"  {GREEN}Patch strategy      : {patch_result['strategy']}{RESET}")
    else:
        print(f"  {RED}Could not produce a verified fix in {MAX_ITERATIONS} iterations plus final fallback.{RESET}")
        print(f"  {YELLOW}Review the logs and regression results above.{RESET}")

    return verified


if __name__ == "__main__":
    run()
