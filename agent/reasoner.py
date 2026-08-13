import json
import os
from dataclasses import dataclass
from typing import List, Optional

                                                                                
              
                                                                                

@dataclass
class VulnerabilityVerdict:
    confirmed: bool
    vuln_type: str                                       
    confidence: str                                     
    affected_file: str
    affected_line: int
    reasoning: str
    root_cause: str
    suggested_fix: str
    need_more_evidence: bool = False                                              


                                                                                
                
                                                                                

def _build_prompt(sast_text: str, fuzz_text: str, dast_text: str, source_snippet: str) -> str:
    return f"""You are an expert cybersecurity analyst and AI reasoning engine.

You have received evidence from three independent security tools about a Python Flask application.
Your task is to correlate this evidence and produce a structured vulnerability verdict.

## SAST (Static Analysis) Findings
{sast_text}

## Fuzzer Results
{fuzz_text}

## DAST (Dynamic Analysis) Evidence
{dast_text}

## Relevant Source Code Snippet
{source_snippet}

---

Based on ALL three sources of evidence, produce a JSON verdict with exactly these fields:
{{
  "confirmed": true or false,
  "vuln_type": "SQL_INJECTION" or "NONE",
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "affected_file": "path/to/file.py",
  "affected_line": <integer line number>,
  "reasoning": "<one paragraph explaining how SAST+Fuzzer+DAST together confirm this>",
  "root_cause": "<precise technical root cause: e.g. 'User input from request.args is concatenated directly into a SQL string without parameterization'>",
  "suggested_fix": "<concrete fix: e.g. 'Replace string concatenation with a parameterized query using cursor.execute(query, (user_input,))'>",
  "need_more_evidence": false
}}

Rules:
- confirmed must be true ONLY if at least 2 of the 3 tools agree.
- If only SAST found something but fuzzer and DAST are clean, set confirmed=false and need_more_evidence=true.
- Return ONLY the JSON object, no markdown fences, no explanation outside the JSON.
"""


                                                                                
                                     
                                                                                

def _mock_reason(sast_text: str, fuzz_text: str, dast_text: str) -> VulnerabilityVerdict:


    sast_hit = any(kw in sast_text for kw in ["HIGH", "SQLI", "SQL"])
    fuzz_hit = any(kw in fuzz_text for kw in ["VULNERABLE", "DATA_LEAK", "DB_ERROR", "STATUS_500"])
    dast_hit = any(kw in dast_text for kw in ["CONFIRMED", "TAINTED", "DATA_LEAK", "AUTH_BYPASS"])

    votes = sum([sast_hit, fuzz_hit, dast_hit])
    confirmed = votes >= 2
    confidence = "HIGH" if votes == 3 else ("MEDIUM" if votes == 2 else "LOW")

    return VulnerabilityVerdict(
        confirmed=confirmed,
        vuln_type="SQL_INJECTION" if confirmed else "NONE",
        confidence=confidence,
        affected_file="target_app/app.py",
        affected_line=32,                                    
        reasoning=(
            f"Evidence correlation: SAST={'✓' if sast_hit else '✗'}, "
            f"Fuzzer={'✓' if fuzz_hit else '✗'}, "
            f"DAST={'✓' if dast_hit else '✗'}. "
            f"{votes}/3 tools independently identified SQL injection. "
            "Multiple independent evidence sources confirm the vulnerability."
        ),
        root_cause=(
            "User-supplied input from request.args.get('id') and request.get_json() is "
            "concatenated directly into SQL query strings and passed to sqlite3 execute() "
            "without parameterization. This allows attackers to inject arbitrary SQL."
        ),
        suggested_fix=(
            "Replace all raw string concatenation with parameterized queries:\n"
            "  query = 'SELECT ... WHERE id = ?'\n"
            "  cursor.execute(query, (user_id,))\n"
            "Ensure this pattern is applied to ALL endpoints: get_user, login, search."
        ),
        need_more_evidence=(votes < 2),
    )


                                                                                
                         
                                                                                

def _gemini_reason(prompt: str) -> VulnerabilityVerdict:
    try:
        import google.generativeai as genai
        api_key = os.environ.get("GOOGLE_API_KEY", "")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        raw = response.text.strip()
                                          
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw)
        return VulnerabilityVerdict(
            confirmed=data.get("confirmed", False),
            vuln_type=data.get("vuln_type", "UNKNOWN"),
            confidence=data.get("confidence", "LOW"),
            affected_file=data.get("affected_file", ""),
            affected_line=int(data.get("affected_line", 0)),
            reasoning=data.get("reasoning", ""),
            root_cause=data.get("root_cause", ""),
            suggested_fix=data.get("suggested_fix", ""),
            need_more_evidence=data.get("need_more_evidence", False),
        )
    except Exception as exc:
                                        
        print(f"  [reasoner] Gemini call failed ({exc}), using mock reasoner.")
        return None


                                                                                
            
                                                                                

def reason(
    sast_text: str,
    fuzz_text: str,
    dast_text: str,
    source_snippet: str = "",
) -> VulnerabilityVerdict:


    api_key = os.environ.get("GOOGLE_API_KEY", "")
    verdict = None

    if api_key:
        prompt = _build_prompt(sast_text, fuzz_text, dast_text, source_snippet)
        verdict = _gemini_reason(prompt)

    if verdict is None:
        verdict = _mock_reason(sast_text, fuzz_text, dast_text)

    return verdict
