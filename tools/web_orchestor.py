import argparse
import concurrent.futures
import json
import logging
import os
import subprocess
import sys
import time
from typing import Dict, List
import requests

from fuzzer import TargetResolver, SASTDrivenFuzzer, parse_sast_json, NormalizedFinding

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class TargetAppManager:
    def __init__(self, base_port: int = 5001):
        self.base_port = base_port
        self.processes: Dict[str, subprocess.Popen] = {}
        self.file_port_map: Dict[str, int] = {}

    def start_targets(self, target_files: List[str], max_targets: int = 3) -> Dict[str, int]:
        active_files = [f for f in target_files if os.path.exists(f)][:max_targets]

        for idx, file_path in enumerate(active_files):
            port = self.base_port + idx
            env = os.environ.copy()
            env["PORT"] = str(port)
            env["FLASK_RUN_PORT"] = str(port)

            app_dir = os.path.dirname(os.path.abspath(file_path))
            app_filename = os.path.basename(file_path)
            
            logging.info(f"Starting target: {app_filename} on port {port} in dir {app_dir}...")
            
            proc = subprocess.Popen(
                [sys.executable, app_filename],
                env=env,
                cwd=app_dir, 
                stdout=subprocess.DEVNULL,
                stderr=sys.stderr,
                preexec_fn=os.setsid if os.name != "nt" else None
            )
            self.processes[file_path] = proc
            self.file_port_map[file_path] = port

            time.sleep(1.5)

        self._wait_for_health(timeout=6.0)
        return self.file_port_map

    def _wait_for_health(self, timeout: float):
        start_time = time.time()
        for file_path, port in self.file_port_map.items():
            url = f"http://127.0.0.1:{port}"
            healthy = False
            while time.time() - start_time < timeout:
                try:
                    requests.get(url, timeout=0.5)
                    healthy = True
                    break
                except (requests.ConnectionError, requests.Timeout):
                    time.sleep(0.3)
            
            if healthy:
                logging.info(f"Server {os.path.basename(file_path)} is ONLINE at {url}")
            else:
                logging.warning(f"Server {os.path.basename(file_path)} on port {port} not responding yet.")

    def stop_all(self):
        logging.info("Cleaning up background target processes...")
        for file_path, proc in self.processes.items():
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()
        self.processes.clear()


def fuzz_worker(file_path: str, port: int, findings: List[NormalizedFinding], src_dir: str) -> List[Dict]:
    base_url = f"http://127.0.0.1:{port}"
    resolver = TargetResolver(src_dir)
    fuzzer = SASTDrivenFuzzer(base_url)

    target_results = []
    for finding in findings:
        target = resolver.resolve(finding)
        result = fuzzer.fuzz_target(finding, target)
        
        result_dict = {
            "finding_id": result.finding_id,
            "target_file": os.path.basename(file_path),
            "port": port,
            "target": {
                "endpoint": target.endpoint,
                "method": target.method,
                "param": target.param,
                "location": target.location,
                "resolved": target.resolved,
                "unresolved_reason": target.unresolved_reason
            },
            "vulnerable": result.vulnerable,
            "payloads_tried": result.payloads_tried,
            "error_state": result.error_state,
            "hits": [
                {
                    "payload": h.payload,
                    "anomaly_type": h.anomaly_type,
                    "evidence_strength": h.evidence_strength,
                    "status_code": h.status_code,
                    "confirmed": h.confirmed,
                    "response_snippet": h.response_snippet
                } for h in result.hits
            ]
        }
        target_results.append(result_dict)

    return target_results


def run_orchestrator(sast_json: str, src_dir: str, base_port: int, max_apps: int, output_file: str):
    findings = parse_sast_json(sast_json)
    if not findings:
        logging.error("No findings found in SAST JSON.")
        return

    findings_by_file: Dict[str, List[NormalizedFinding]] = {}
    for f in findings:
        findings_by_file.setdefault(f.file_path, []).append(f)

    # Filter out test files
    unique_files = [f for f in findings_by_file.keys() if not os.path.basename(f).startswith("test_")]
    logging.info(f"Identified {len(unique_files)} valid target apps: {[os.path.basename(f) for f in unique_files]}")

    manager = TargetAppManager(base_port=base_port)
    try:
        active_port_map = manager.start_targets(unique_files, max_targets=max_apps)
        
        all_results = []
        logging.info("Starting simultaneous fuzzing pipeline across active instances...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(active_port_map)) as executor:
            future_to_file = {
                executor.submit(fuzz_worker, fpath, port, findings_by_file[fpath], src_dir): fpath
                for fpath, port in active_port_map.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                fpath = future_to_file[future]
                try:
                    file_results = future.result()
                    all_results.extend(file_results)
                except Exception as exc:
                    logging.error(f"Execution generated an exception for {fpath}: {exc}")

        report = {
            "metadata": {
                "total_targets_loaded": len(active_port_map),
                "total_findings_processed": len(all_results),
                "vulnerabilities_confirmed": sum(1 for r in all_results if r["vulnerable"]),
                "ports_used": list(active_port_map.values())
            },
            "results": all_results
        }

        with open(output_file, "w", encoding="utf-8") as out:
            json.dump(report, out, indent=2)

        logging.info(f"Fuzzing complete! Detailed JSON report saved to: {output_file}")
        print(f"\n[+] Scan Complete — {report['metadata']['vulnerabilities_confirmed']} confirmed vulnerable endpoints across {len(active_port_map)} target apps.")

    finally:
        manager.stop_all()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Target Automated Fuzzing Orchestrator")
    parser.add_argument("--sast-json", default="sast_web_queue.json", help="Path to SAST JSON file")
    parser.add_argument("--src-dir", default="../target_app", help="Path to source directory")
    parser.add_argument("--base-port", type=int, default=5001, help="Starting localhost port")
    parser.add_argument("--max-apps", type=int, default=3, help="Max target apps to run concurrently")
    parser.add_argument("--out", default="report.json", help="Output JSON path")
    args = parser.parse_args()

    run_orchestrator(args.sast_json, args.src_dir, args.base_port, args.max_apps, args.out)