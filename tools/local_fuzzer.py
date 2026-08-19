import argparse
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Tuple

# Import shared components directly from your web fuzzer
from fuzzer import PayloadRegistry, NormalizedFinding, parse_sast_json

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ============================================================================
# LOCAL DATA MODELS (Unbiased, Data-Gathering Only)
# ============================================================================

@dataclass
class LocalTarget:
    filepath: str
    execution_method: str = "argv"  # How payload is passed: "argv", "stdin", "env"
    target_param: str = "1"         # Index for argv, or key for env
    resolved: bool = True
    unresolved_reason: str = ""

@dataclass
class LocalBaselineProfile:
    exit_code: int
    execution_time: float
    stdout_len: int
    stderr_len: int

@dataclass
class LocalFuzzHit:
    finding_id: str
    payload: str
    anomaly_type: str
    evidence_strength: str
    exit_code: int
    baseline_time: float
    fuzz_time: float
    stderr_snippet: str
    stdout_snippet: str
    execution_artifact: Dict = field(default_factory=dict)

@dataclass
class LocalFuzzResult:
    finding_id: str
    target: LocalTarget
    hits: List[LocalFuzzHit] = field(default_factory=list)
    payloads_tried: int = 0
    error_state: str = ""

# ============================================================================
# LOCAL TARGET RESOLVER
# ============================================================================

class LocalTargetResolver:
    """Resolves SAST findings to local execution strategies."""
    def __init__(self, base_dir: str):
        self.base_dir = base_dir

    def resolve(self, finding: NormalizedFinding) -> LocalTarget:
        full_path = os.path.join(self.base_dir, finding.file_path)
        if not os.path.exists(full_path):
            return LocalTarget(full_path, resolved=False, unresolved_reason="File not found")

        # For simplicity in this local harness, we assume the payload needs to be 
        # passed as the first command-line argument. This can be expanded to parse
        # the AST and determine if it expects stdin (e.g., input()) or env vars.
        execution_method = "argv"
        
        if "input(" in finding.snippet or "sys.stdin" in finding.snippet:
            execution_method = "stdin"
        elif "os.environ" in finding.snippet:
            execution_method = "env"

        return LocalTarget(full_path, execution_method=execution_method)

# ============================================================================
# LOCAL SUBPROCESS FUZZER
# ============================================================================

class LocalSASTFuzzer:
    def __init__(self, timeout: float = 3.0, time_threshold: float = 1.0):
        self.timeout = timeout
        self.time_threshold = time_threshold
        self.registry = PayloadRegistry()
        self.baseline_cache: Dict[str, LocalBaselineProfile] = {}

    def _execute_harness(self, target: LocalTarget, payload: str) -> Tuple[int, str, str, float]:
        """Safely executes the target script with the payload and captures OS signals."""
        cmd = []
        # If it's a python script, run with the current python interpreter
        if target.filepath.endswith(".py"):
            cmd.append(sys.executable)
        cmd.append(target.filepath)

        env = os.environ.copy()
        stdin_data = None

        if target.execution_method == "argv":
            cmd.append(payload)
        elif target.execution_method == "env":
            env["FUZZ_PAYLOAD"] = payload  # Simplified assumption
        elif target.execution_method == "stdin":
            stdin_data = payload

        t0 = time.perf_counter()
        try:
            process = subprocess.run(
                cmd,
                input=stdin_data,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            duration = time.perf_counter() - t0
            return process.returncode, process.stdout, process.stderr, duration
        
        except subprocess.TimeoutExpired as e:
            duration = time.perf_counter() - t0
            # Return -1 to indicate timeout, capture whatever output was available before death
            stdout = e.stdout.decode() if e.stdout else ""
            stderr = e.stderr.decode() if e.stderr else "TIMEOUT EXPIRED"
            return -1, stdout, stderr, duration
        except Exception as e:
            duration = time.perf_counter() - t0
            return -2, "", str(e), duration

    def _get_baseline(self, target: LocalTarget) -> LocalBaselineProfile:
        if target.filepath in self.baseline_cache:
            return self.baseline_cache[target.filepath]

        safe_value = "safe_baseline_123"
        exit_code, stdout, stderr, duration = self._execute_harness(target, safe_value)
        
        profile = LocalBaselineProfile(exit_code, duration, len(stdout), len(stderr))
        self.baseline_cache[target.filepath] = profile
        return profile

    def _detect_anomaly(self, exit_code: int, stderr: str, duration: float, baseline: LocalBaselineProfile) -> Tuple[Optional[str], str]:
        stderr_lower = stderr.lower()
        
        # 1. Timeout / Hanging process
        if exit_code == -1 or (duration - baseline.execution_time > self.time_threshold):
            return "PROCESS_TIMEOUT", "Strong"

        # 2. Unhandled Exception / Traceback Leak
        if "traceback (most recent call last):" in stderr_lower or "exception:" in stderr_lower:
            return "UNHANDLED_EXCEPTION", "Very Strong"

        # 3. Memory or OS Error (Segfaults usually return negative exit codes on POSIX)
        if exit_code < 0 and exit_code != -1:
            return "OS_SIGNAL_CRASH", "Very Strong"

        # 4. Standard Crash (Non-zero exit code when baseline was 0)
        if exit_code != 0 and baseline.exit_code == 0:
            return "ABNORMAL_EXIT", "Medium"

        return None, "None"

    def fuzz_target(self, finding: NormalizedFinding, target: LocalTarget) -> LocalFuzzResult:
        result = LocalFuzzResult(finding.finding_id, target)
        if not target.resolved:
            result.error_state = f"TARGET_UNRESOLVED: {target.unresolved_reason}"
            return result

        baseline = self._get_baseline(target)
        payloads = self.registry.get_payloads_for_finding(finding.rule_id)
        
        for payload in payloads:
            result.payloads_tried += 1
            
            exit_code, stdout, stderr, duration = self._execute_harness(target, payload)
            anomaly, strength = self._detect_anomaly(exit_code, stderr, duration, baseline)
            
            # Record everything anomalous, do not break.
            if anomaly:
                hit = LocalFuzzHit(
                    finding_id=finding.finding_id,
                    payload=payload,
                    anomaly_type=anomaly,
                    evidence_strength=strength,
                    exit_code=exit_code,
                    baseline_time=baseline.execution_time,
                    fuzz_time=duration,
                    stderr_snippet=stderr.replace("\n", " ").strip()[:250],
                    stdout_snippet=stdout.replace("\n", " ").strip()[:100],
                    execution_artifact={"method": target.execution_method, "cmd_args_used": target.execution_method == "argv"}
                )
                result.hits.append(hit)

        return result

# ============================================================================
# ORCHESTRATION & OUTPUT
# ============================================================================

def run_local_pipeline(sast_file: str, base_dir: str, out_file: str):
    findings = parse_sast_json(sast_file)
    if not findings:
        logging.error("No findings found in SAST JSON.")
        return

    resolver = LocalTargetResolver(base_dir)
    fuzzer = LocalSASTFuzzer()
    
    all_results = []
    logging.info(f"Starting local fuzzing pipeline on {len(findings)} findings...")
    
    for finding in findings:
        target = resolver.resolve(finding)
        result = fuzzer.fuzz_target(finding, target)
        all_results.append(asdict(result))

    report = {
        "metadata": {
            "total_findings_processed": len(findings),
            "total_anomalies_found": sum(len(r["hits"]) for r in all_results),
            "execution_type": "local_subprocess"
        },
        "results": all_results
    }

    with open(out_file, "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)

    print(f"\n[+] Local Scan Complete — {report['metadata']['total_anomalies_found']} anomalies found locally.")
    logging.info(f"Detailed JSON report saved to: {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAST-Driven Local Subprocess Fuzzer")
    parser.add_argument("--sast-json", default="sast_local_queue.json", help="Path to SAST JSON output")
    parser.add_argument("--src-dir", default=".", help="Base directory of source code for resolution")
    parser.add_argument("--out", default="local_report.json", help="Output format")
    args = parser.parse_args()
    
    run_local_pipeline(args.sast_json, args.src_dir, args.out)