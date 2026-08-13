import json
import os
import time
import requests
from dataclasses import dataclass, asdict
from typing import List, Optional


RESULTS_DIR = os.path.join(os.path.dirname(__file__), "security_results")
os.makedirs(RESULTS_DIR, exist_ok=True)


                                                                                
                 
                                                                                

@dataclass
class SecurityTestCase:
    test_id: str                                  
    description: str
    endpoint: str                                   
    method: str                           
    params: dict                                         
    exploit_payload: str                                                           
                                
    pre_patch_status: Optional[str] = None                           
    post_patch_status: Optional[str] = None                          
    pre_patch_response: Optional[str] = None
    post_patch_response: Optional[str] = None


@dataclass
class ReplayResult:
    test_id: str
    phase: str                                            
    status: str                                             
    http_code: int
    response_snippet: str
    assertion: str                              
    passed: bool


                                                                                
                                  
                                                                                

SECURITY_TEST_CASES: List[SecurityTestCase] = [
    SecurityTestCase(
        test_id="SEC-SQL-001",
        description="SQL injection via GET /api/user id parameter (OR 1=1 tautology)",
        endpoint="/api/user",
        method="GET",
        params={"id": "1 OR 1=1--"},
        exploit_payload="1 OR 1=1--",
    ),
    SecurityTestCase(
        test_id="SEC-SQL-002",
        description="SQL injection via GET /api/user id parameter (UNION data dump)",
        endpoint="/api/user",
        method="GET",
        params={"id": "' UNION SELECT 1,username,password FROM users--"},
        exploit_payload="' UNION SELECT 1,username,password FROM users--",
    ),
    SecurityTestCase(
        test_id="SEC-SQL-003",
        description="SQL auth bypass via POST /api/login username field",
        endpoint="/api/login",
        method="POST",
        params={"username": "admin'--", "password": "anything"},
        exploit_payload="admin'--",
    ),
    SecurityTestCase(
        test_id="SEC-SQL-004",
        description="SQL auth bypass via POST /api/login (OR tautology)",
        endpoint="/api/login",
        method="POST",
        params={"username": "' OR '1'='1", "password": "' OR '1'='1"},
        exploit_payload="' OR '1'='1",
    ),
    SecurityTestCase(
        test_id="SEC-SQL-005",
        description="SQL injection via GET /api/search q parameter",
        endpoint="/api/search",
        method="GET",
        params={"q": "' OR '1'='1"},
        exploit_payload="' OR '1'='1",
    ),
]


                                                                                
                 
                                                                                

LEAK_SIGNATURES = ["password", "secret123", "qwerty", "letmein"]
ERROR_SIGNATURES = ["operationalerror", "sqlite", "syntax error", "unrecognized token"]


def _is_vulnerable(response: requests.Response) -> bool:


    body = response.text.lower()

                            
    if response.status_code == 500:
        if any(s in body for s in ERROR_SIGNATURES):
            return True

                                                       
    if response.status_code == 200:
                                                                           
        try:
            data = response.json()
            if isinstance(data, list) and len(data) > 2:
                return True
        except Exception:
            pass
        if any(s in body for s in LEAK_SIGNATURES):
            return True

                                                       
    if "login" in response.url and response.status_code == 200:
        try:
            data = response.json()
            if data.get("authenticated") is True:
                return True
        except Exception:
            pass

    return False


                                                                                
          
                                                                                

def replay_test(base_url: str, tc: SecurityTestCase, phase: str) -> ReplayResult:


    url = base_url.rstrip("/") + tc.endpoint
    try:
        if tc.method == "GET":
            resp = requests.get(url, params=tc.params, timeout=5)
        else:
            resp = requests.post(url, json=tc.params, timeout=5)

        vulnerable = _is_vulnerable(resp)
        snippet = resp.text[:300].replace("\n", " ").strip()

        if phase == "pre_patch":
                                                                      
            status = "VULNERABLE" if vulnerable else "BLOCKED"
            expected = "VULNERABLE"
            passed = vulnerable
        else:
                                                                      
            status = "BLOCKED" if not vulnerable else "VULNERABLE"
            expected = "BLOCKED"
            passed = not vulnerable

        return ReplayResult(
            test_id=tc.test_id,
            phase=phase,
            status=status,
            http_code=resp.status_code,
            response_snippet=snippet,
            assertion=f"Expected {expected}",
            passed=passed,
        )

    except Exception as exc:
        return ReplayResult(
            test_id=tc.test_id,
            phase=phase,
            status="ERROR",
            http_code=0,
            response_snippet=str(exc),
            assertion=f"Expected {'VULNERABLE' if phase == 'pre_patch' else 'BLOCKED'}",
            passed=False,
        )


def run_security_regression(base_url: str, phase: str) -> List[ReplayResult]:


    results = []
    for tc in SECURITY_TEST_CASES:
        result = replay_test(base_url, tc, phase)
        results.append(result)
                        
        _save_result(tc.test_id, phase, result)
    return results


def _save_result(test_id: str, phase: str, result: ReplayResult):
    path = os.path.join(RESULTS_DIR, f"{test_id}_{phase}.json")
    with open(path, "w") as f:
        json.dump(asdict(result), f, indent=2)


                                                                                
                  
                                                                                

def format_security_report(results: List[ReplayResult], phase: str) -> str:
    lines = []
    lines.append(f"\n  ── Security Regression ({phase.replace('_', ' ').title()}) ──")
    passed = sum(1 for r in results if r.passed)
    for r in results:
        icon = "✓" if r.passed else "✗"
        color = "\033[92m" if r.passed else "\033[91m"
        reset = "\033[0m"
        lines.append(
            f"  {color}{icon}{reset}  {r.test_id:<14} "
            f"{r.status:<12}  HTTP {r.http_code}"
        )
    lines.append(f"\n  Result: {passed}/{len(results)} passed")
    return "\n".join(lines)
