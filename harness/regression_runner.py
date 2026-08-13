import os
import sys
import json
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class TestResult:
    test_id: str
    outcome: str                                   
    duration: float
    message: str = ""


@dataclass
class RegressionReport:
    total: int
    passed: int
    failed: int
    errors: int
    duration: float
    tests: List[TestResult]

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.errors == 0

    def summary(self) -> str:
        icon = "✓" if self.all_passed else "✗"
        color = "\033[92m" if self.all_passed else "\033[91m"
        reset = "\033[0m"
        return (
            f"  {color}{icon}{reset} "
            f"{self.passed}/{self.total} tests passed  "
            f"({self.failed} failed, {self.errors} errors)  "
            f"[{self.duration:.2f}s]"
        )


def run_regression(
    repo_root: str,
    test_file: str = "harness/test_target_app.py",
    extra_pythonpath: str = "",
) -> RegressionReport:


    report_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    report_file.close()

    env = os.environ.copy()
                                                            
    paths = [repo_root, os.path.join(repo_root, "target_app")]
    if extra_pythonpath:
        paths.append(extra_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(paths)

    cmd = [
        sys.executable, "-m", "pytest",
        test_file,
        "--tb=short",
        f"--json-report",
        f"--json-report-file={report_file.name}",
        "-q",
    ]

    result = subprocess.run(
        cmd,
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
    )

                           
    try:
        with open(report_file.name) as f:
            data = json.load(f)

        tests = []
        for item in data.get("tests", []):
            tests.append(TestResult(
                test_id=item.get("nodeid", ""),
                outcome=item.get("outcome", "unknown"),
                duration=item.get("duration", 0.0),
                message=(
                    item.get("call", {}).get("longrepr", "")
                    if item.get("outcome") != "passed" else ""
                ),
            ))

        summary = data.get("summary", {})
        return RegressionReport(
            total=summary.get("total", len(tests)),
            passed=summary.get("passed", 0),
            failed=summary.get("failed", 0),
            errors=summary.get("error", 0),
            duration=data.get("duration", 0.0),
            tests=tests,
        )

    except Exception:
                                     
        passed = failed = errors = 0
        for line in result.stdout.splitlines():
            if "passed" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "passed" and i > 0:
                        try:
                            passed = int(parts[i - 1])
                        except ValueError:
                            pass
                    if p == "failed" and i > 0:
                        try:
                            failed = int(parts[i - 1])
                        except ValueError:
                            pass

        return RegressionReport(
            total=passed + failed + errors,
            passed=passed,
            failed=failed,
            errors=errors,
            duration=0.0,
            tests=[],
        )
    finally:
        try:
            os.unlink(report_file.name)
        except OSError:
            pass


def print_report(report: RegressionReport):
    print("\n  ── Functional Regression Tests ──")
    if report.tests:
        for t in report.tests:
            icon = "✓" if t.outcome == "passed" else "✗"
            color = "\033[92m" if t.outcome == "passed" else "\033[91m"
            reset = "\033[0m"
            name = t.test_id.split("::")[-1]
            print(f"  {color}{icon}{reset}  {name:<45}  [{t.outcome}]")
            if t.message:
                for line in t.message.splitlines()[:3]:
                    print(f"      \033[90m{line}\033[0m")
    print(f"\n  {report.summary()}")
