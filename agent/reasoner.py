import json
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

                                                                                
              
                                                                                

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


                                                                                
                         
                                                                                

import re
from agent.llm_client import query_llm, get_active_provider

def _extract_json_block(text: str) -> Optional[dict]:
    """Extract and parse JSON object from LLM response with balanced brace extraction."""
    if not text:
        return None
    
    clean_text = text.strip()
    try:
        return json.loads(clean_text)
    except Exception:
        pass

    # If wrapped in markdown code blocks
    if "```" in clean_text:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", clean_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except Exception:
                pass

    # Balanced curly brace extraction
    start_idx = clean_text.find("{")
    if start_idx != -1:
        depth = 0
        end_idx = -1
        in_string = False
        escape = False
        for i in range(start_idx, len(clean_text)):
            c = clean_text[i]
            if escape:
                escape = False
                continue
            if c == "\\":
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if not in_string:
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        end_idx = i + 1
                        break
        if end_idx != -1:
            candidate = clean_text[start_idx:end_idx]
            try:
                return json.loads(candidate)
            except Exception:
                cleaned_commas = re.sub(r",\s*([\}\]])", r"\1", candidate)
                try:
                    return json.loads(cleaned_commas)
                except Exception:
                    pass

    return None

def _llm_reason(prompt: str) -> Tuple[Optional[VulnerabilityVerdict], str]:
    raw_response, provider_info = query_llm(prompt, response_format="json")
    if not raw_response:
        return None, provider_info

    data = _extract_json_block(raw_response)
    if not data or not isinstance(data, dict):
        print(f"  [reasoner] Could not parse valid JSON from {provider_info} output, falling back to mock.")
        return None, provider_info

    try:
        verdict = VulnerabilityVerdict(
            confirmed=bool(data.get("confirmed", False)),
            vuln_type=str(data.get("vuln_type", "UNKNOWN")),
            confidence=str(data.get("confidence", "LOW")),
            affected_file=str(data.get("affected_file", "target_app/app.py")),
            affected_line=int(data.get("affected_line", 0) or 0),
            reasoning=str(data.get("reasoning", "")),
            root_cause=str(data.get("root_cause", "")),
            suggested_fix=str(data.get("suggested_fix", "")),
            need_more_evidence=bool(data.get("need_more_evidence", False)),
        )
        return verdict, provider_info
    except Exception as exc:
        print(f"  [reasoner] Error parsing verdict from {provider_info} ({exc})")
        return None, provider_info


# ==============================================================================
# Public API
# ==============================================================================

def reason(
    sast_text: str,
    fuzz_text: str,
    dast_text: str,
    source_snippet: str = "",
) -> VulnerabilityVerdict:
    """
    Correlate multi-tool findings and produce a vulnerability verdict.
    Uses local Ollama LLM if available, or deterministic offline mock.
    """
    prompt = _build_prompt(sast_text, fuzz_text, dast_text, source_snippet)
    verdict, provider_info = _llm_reason(prompt)

    if verdict is not None:
        print(f"  [reasoner] Correlated evidence using LLM provider: {provider_info}")
        return verdict

    print(f"  [reasoner] Using deterministic rule-based mock reasoner.")
    return _mock_reason(sast_text, fuzz_text, dast_text)

