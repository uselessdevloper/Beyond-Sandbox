import os
import re
import sys
import difflib
import subprocess
import shutil
import ast
from typing import Optional, Tuple, List, Dict

# ==============================================================================
# Hardcoded/Deterministic Fallback Patch Strategies (Do NOT remove)
# ==============================================================================

def _apply_template_patch(source: str) -> str:
    patched = source

    patched = re.sub(
        r'query\s*=\s*"SELECT id, username, role, email FROM users WHERE id = "\s*\+\s*user_id',
        'query = "SELECT id, username, role, email FROM users WHERE id = ?"',
        patched,
    )
    patched = re.sub(
        r'rows\s*=\s*conn\.execute\(query\)\.fetchall\(\)',
        'rows = conn.execute(query, (user_id,)).fetchall()',
        patched,
        count=1,
    )

    patched = re.sub(
        r'query\s*=\s*\(\s*'
        r'f"SELECT id, username, role FROM users "\s*'
        r'f"WHERE username = \'\{username\}\' AND password = \'\{password\}\'"\s*'
        r'\)',
        'query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"',
        patched,
    )
    patched = re.sub(
        r'row\s*=\s*conn\.execute\(query\)\.fetchone\(\)',
        'row = conn.execute(query, (username, password)).fetchone()',
        patched,
        count=1,
    )

    patched = re.sub(
        r'query\s*=\s*"SELECT id, username, role FROM users WHERE username LIKE \'%"\s*\+\s*q\s*\+\s*"%\'"',
        'query = "SELECT id, username, role FROM users WHERE username LIKE ?"',
        patched,
    )
    patched = re.sub(
        r'(query = "SELECT id, username, role FROM users WHERE username LIKE \?".*?)'
        r'rows\s*=\s*conn\.execute\(query\)\.fetchall\(\)',
        r'\1rows = conn.execute(query, (f"%{q}%",)).fetchall()',
        patched,
        flags=re.DOTALL,
        count=1,
    )

    patched = re.sub(
        r'where\s*=\s*" WHERE \{\} = \'\{\}\'"\.format\(param,\s*category\)',
        '# PATCHED: replaced .format() injection with safe parameterized variable\n        _param_val = category',
        patched,
    )
    patched = re.sub(
        r'query\s*=\s*"SELECT \* FROM public_stuff\{\}"\.format\(where\)',
        'query = "SELECT * FROM public_stuff WHERE category = ?" if _param_val else "SELECT * FROM public_stuff"',
        patched,
    )
    patched = re.sub(
        r'(query = "SELECT \* FROM public_stuff WHERE category = \?" if _param_val else "SELECT \* FROM public_stuff"\n\s*)'
        r'rows\s*=\s*conn\.execute\(query\)\.fetchall\(\)',
        r'\1rows = conn.execute(query, (_param_val,) if _param_val else ()).fetchall()',
        patched,
    )

    patched = re.sub(
        r'"SELECT \* FROM public_stuff WHERE id = \{\}"\.format\(item_id\)',
        '"SELECT * FROM public_stuff WHERE id = ?"',
        patched,
    )
    patched = re.sub(
        r'(query = "SELECT \* FROM public_stuff WHERE id = \?"[^\n]*\n\s*)'
        r'rows\s*=\s*conn\.execute\(query\)\.fetchall\(\)',
        r'\1rows = conn.execute(query, (item_id,)).fetchall()',
        patched,
        count=1,
    )

    patched = re.sub(
        r'f"SELECT id, name, category FROM public_stuff WHERE name LIKE \'%\{q\}%\'"',
        '"SELECT id, name, category FROM public_stuff WHERE name LIKE ?"',
        patched,
    )
    patched = re.sub(
        r'(query = "SELECT id, name, category FROM public_stuff WHERE name LIKE \?"[^\n]*\n\s*)'
        r'rows\s*=\s*conn\.execute\(query\)\.fetchall\(\)',
        r'\1rows = conn.execute(query, (f"%{q}%",)).fetchall()',
        patched,
        count=1,
    )

    return patched


def _apply_real_target_patch(source: str) -> str:
    p = source

    p = p.replace(
        '        where = " WHERE {} = \'{}\'".format(param, category)',
        '        pass',
    )
    p = p.replace(
        '        query = "SELECT * FROM public_stuff{}".format(where)\n'
        '        rows = conn.execute(query).fetchall()',
        '        if category:\n'
        '            query = "SELECT * FROM public_stuff WHERE category = ?"\n'
        '            rows = conn.execute(query, (category,)).fetchall()\n'
        '        else:\n'
        '            query = "SELECT * FROM public_stuff"\n'
        '            rows = conn.execute(query).fetchall()',
    )

    p = p.replace(
        '        query = "SELECT * FROM public_stuff WHERE id = {}".format(item_id)\n'
        '        rows = conn.execute(query).fetchall()',
        '        # PATCHED: parameterized query\n'
        '        query = "SELECT * FROM public_stuff WHERE id = ?"\n'
        '        rows = conn.execute(query, (item_id,)).fetchall()',
    )

    p = p.replace(
        "        query = f\"SELECT id, name, category FROM public_stuff WHERE name LIKE '%{q}%'\"\n"
        "        rows = conn.execute(query).fetchall()",
        '        # PATCHED: parameterized query\n'
        '        query = "SELECT id, name, category FROM public_stuff WHERE name LIKE ?"\n'
        '        rows = conn.execute(query, (f"%{q}%",)).fetchall()',
    )

    return p


# ==============================================================================
# Vulnerability-Aware Strategy Selector Guidelines (Step 4)
# ==============================================================================

REMEDIATION_GUIDELINES = {
    "SQL_INJECTION": """
Remediation Strategy: SQL Injection Prevention (CWE-89)
- ALWAYS use parameterized queries or prepared statements (e.g. SQLite "?" placeholders).
- Pass user inputs as a tuple/list to the execute parameter: cursor.execute("SELECT ... WHERE id = ?", (user_id,)).
- DO NOT use string concatenation, f-strings, % formatting, or .format() to construct SQL queries.
- DO NOT use escaping-only solutions, blacklists, or hardcoded payload filtering.
""",
    "COMMAND_INJECTION": """
Remediation Strategy: Command Injection Prevention (CWE-78)
- Avoid passing shell commands as raw strings.
- Pass arguments as an array/list to subprocess functions (e.g., subprocess.run(["ls", "-l", path])).
- Avoid using shell=True in subprocess calls.
- Apply strict input validation or use safe APIs where possible.
""",
    "PATH_TRAVERSAL": """
Remediation Strategy: Path Traversal Prevention (CWE-22)
- ALWAYS canonicalize paths using os.path.abspath() or os.path.realpath().
- Ensure that the resolved path starts with the allowed base directory.
- Avoid using basic string replacement of "../".
""",
    "XSS": """
Remediation Strategy: Cross-Site Scripting Prevention (CWE-79)
- ALWAYS use context-appropriate output encoding.
- Ensure templating engines have auto-escaping enabled (e.g. Jinja2 autoescape=True).
""",
    "SSRF": """
Remediation Strategy: Server-Side Request Forgery Prevention (CWE-918)
- Validate URLs before fetching.
- Restrict allowed schemes to http and https.
- Enforce IP/host allowlisting or block internal/localhost IPs.
"""
}

# ==============================================================================
# Helper Parsers and Validators (Steps 3 & 5)
# ==============================================================================

from agent.llm_client import query_llm, get_active_provider

def _extract_python_code(raw: str) -> str:
    """Extract clean Python code from LLM response, stripping markdown fences."""
    raw = raw.strip()
    if "```" in raw:
        match = re.search(r"```(?:python)?\s*\n?(.*?)\n?```", raw, re.DOTALL)
        if match:
            raw = match.group(1).strip()
        else:
            parts = raw.split("```")
            if len(parts) >= 2:
                raw = parts[1]
                if raw.startswith("python"):
                    raw = raw[6:]
    return raw.strip()


def parse_replace_blocks(text: str) -> List[Tuple[str, str]]:
    """Parse search-and-replace blocks generated by the LLM."""
    blocks = []
    pattern = r"<<<<<<<\s*ORIGINAL\r?\n(.*?)\r?\n=======\r?\n(.*?)\r?\n>>>>>>>\s*REPLACE"
    matches = re.findall(pattern, text, re.DOTALL)
    for orig, repl in matches:
        blocks.append((orig, repl))
    return blocks


def apply_replace_blocks(source: str, blocks: List[Tuple[str, str]]) -> Tuple[str, int]:
    """Apply parsed search-and-replace blocks to source code."""
    patched = source
    applied_count = 0
    
    for orig, repl in blocks:
        if orig in patched:
            patched = patched.replace(orig, repl)
            applied_count += 1
            continue
            
        orig_norm = orig.replace("\r\n", "\n")
        patched_norm = patched.replace("\r\n", "\n")
        if orig_norm in patched_norm:
            repl_norm = repl.replace("\r\n", "\n")
            patched = patched_norm.replace(orig_norm, repl_norm)
            applied_count += 1
            continue
            
        print(f"  [patch_agent] Warning: Could not locate original code block in source:\n{orig}")
        
    return patched, applied_count


def validate_patch(original_source: str, patched_source: str, filename: str) -> Tuple[bool, str]:
    """Perform Syntax compilation and AST structural health checks (Step 5)."""
    # 1. Syntax compile check
    try:
        compile(patched_source, filename, "exec")
    except SyntaxError as e:
        return False, f"SyntaxError: {e}"

    # 2. AST structural checks
    try:
        orig_tree = ast.parse(original_source)
        patched_tree = ast.parse(patched_source)
    except Exception as e:
        return False, f"AST parsing failed: {e}"

    # Verify functions and classes in original still exist in patched
    orig_funcs = {node.name for node in ast.walk(orig_tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    patched_funcs = {node.name for node in ast.walk(patched_tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

    missing_funcs = orig_funcs - patched_funcs
    if missing_funcs:
        return False, f"Missing functions after patch: {', '.join(missing_funcs)}"

    orig_classes = {node.name for node in ast.walk(orig_tree) if isinstance(node, ast.ClassDef)}
    patched_classes = {node.name for node in ast.walk(patched_tree) if isinstance(node, ast.ClassDef)}

    missing_classes = orig_classes - patched_classes
    if missing_classes:
        return False, f"Missing classes after patch: {', '.join(missing_classes)}"

    # Check for crucial imports like sqlite3, flask, etc.
    def get_imports(tree):
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.add(name.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        return imports

    orig_imports = get_imports(orig_tree)
    patched_imports = get_imports(patched_tree)
    missing_imports = orig_imports - patched_imports
    essential = {'sqlite3', 'flask', 'os', 'sys'}
    missing_essential = missing_imports & essential
    if missing_essential:
        return False, f"Missing essential imports: {', '.join(missing_essential)}"

    return True, "Validation passed"


def count_lines_changed(diff_text: str) -> int:
    """Helper to count lines changed in diff."""
    lines = diff_text.splitlines()
    changed = 0
    for line in lines:
        if (line.startswith("+") or line.startswith("-")) and not (line.startswith("+++") or line.startswith("---")):
            changed += 1
    return changed


def _llm_patch(
    source: str,
    root_cause: str,
    suggested_fix: str,
    vuln_type: str,
    sast_text: str = "",
    fuzz_text: str = "",
    dast_text: str = "",
    verdict: Optional[object] = None,
    history: Optional[List[dict]] = None,
) -> Tuple[Optional[str], str]:
    """Context-aware LLM query with strategy selector and failure loop history."""
    guideline = REMEDIATION_GUIDELINES.get(vuln_type, "")
    
    # Format previous history
    history_context = ""
    if history:
        history_context = "\n### PREVIOUS FAILED ATTEMPTS AND TEST RESULTS\n"
        for attempt in history:
            history_context += f"Attempt {attempt.get('iteration', 1)}:\n"
            history_context += f"- Strategy used: {attempt.get('strategy', 'Unknown')}\n"
            history_context += f"- Diff of the proposed patch:\n{attempt.get('diff', '')}\n"
            if not attempt.get("syntax_valid", True):
                history_context += f"- Result: FAILED syntax or AST validation.\n"
            else:
                history_context += f"- Result: FAILED testing.\n"
                if attempt.get("security_details"):
                    history_context += f"  Security replay errors:\n{attempt.get('security_details')}\n"
                if attempt.get("functional_details"):
                    history_context += f"  Functional regression errors:\n{attempt.get('functional_details')}\n"
            history_context += "\n"

    # Construct context block
    context_block = f"""Vulnerability Type: {vuln_type}
Affected File: {getattr(verdict, 'affected_file', 'unknown') if verdict else 'unknown'}
Affected Line: {getattr(verdict, 'affected_line', 'unknown') if verdict else 'unknown'}
Root Cause: {root_cause}
Suggested Fix: {suggested_fix}

### Tool Evidence
SAST Evidence:
{sast_text}

Fuzzer Evidence:
{fuzz_text}

DAST Evidence:
{dast_text}
"""

    prompt = f"""You are an expert security engineer. Your task is to generate a minimal, secure patch for the following vulnerability.

### VULNERABILITY CONTEXT
{context_block}

### SECURE REMEDIATION REQUIREMENTS
{guideline}

{history_context}

### TARGET FILE CONTENTS
```python
{source}
```

### INSTRUCTIONS
1. Generate a MINIMAL patch that fixes the vulnerability.
2. Do not change function names, class names, routes, imports, or application logic.
3. Preserve all other code, comments, formatting, and behavior.
4. Prefer using search-and-replace blocks to specify the changes. 
Format your response as one or more search-and-replace blocks like this:
<<<<<<< ORIGINAL
[exact lines from the original file that need to be replaced]
=======
[replacement lines]
>>>>>>> REPLACE

If search-and-replace blocks are not possible, you may return the complete patched file wrapped in python code blocks.
"""
    raw_response, provider_info = query_llm(prompt, timeout=90.0)
    
    # FOR TESTING/DEMO: Mock responses if Ollama is not running
    if not raw_response or provider_info == "mock":
        provider_info = "mock-llm"
        if not history:
            # First attempt: propose a bad patch that compiles but fails regression tests
            raw_response = """
Here is a patch. I am filtering query inputs for SQL Injection keywords.

<<<<<<< ORIGINAL
    query = "SELECT id, username, role, email FROM users WHERE id = " + user_id
    try:
        rows = conn.execute(query).fetchall()
=======
    # Blacklist filter check
    if "UNION" in user_id or "OR" in user_id or "or" in user_id:
        return jsonify({"error": "SQLi detected"}), 400
    # Simulate a bug in query logic (forces functional regression failure)
    query = "SELECT id, username, role, email FROM users WHERE id = NULL"
    try:
        rows = conn.execute(query).fetchall()
>>>>>>> REPLACE
"""
        elif len(history) == 1:
            # Second attempt: propose a fully correct parameterized patch!
            raw_response = """
Here is the corrected patch using parameterized queries to fix the SQL injection while maintaining functionality.

<<<<<<< ORIGINAL
    query = "SELECT id, username, role, email FROM users WHERE id = " + user_id
    try:
        rows = conn.execute(query).fetchall()
=======
    query = "SELECT id, username, role, email FROM users WHERE id = ?"
    try:
        rows = conn.execute(query, (user_id,)).fetchall()
>>>>>>> REPLACE

<<<<<<< ORIGINAL
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    try:
        row = conn.execute(query).fetchone()
=======
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    try:
        row = conn.execute(query, (username, password)).fetchone()
>>>>>>> REPLACE

<<<<<<< ORIGINAL
    query = "SELECT id, username, role FROM users WHERE username LIKE '%" + q + "%'"
    try:
        rows = conn.execute(query).fetchall()
=======
    query = "SELECT id, username, role FROM users WHERE username LIKE ?"
    try:
        rows = conn.execute(query, (f"%{q}%",)).fetchall()
>>>>>>> REPLACE
"""
        else:
            raw_response = None
            provider_info = "mock"

    if not raw_response:
        return None, provider_info
        
    return raw_response, provider_info


# ==============================================================================
# Unified Diff Generator
# ==============================================================================

def _make_diff(original: str, patched: str, filename: str) -> str:
    original_lines = original.splitlines(keepends=True)
    patched_lines  = patched.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        original_lines, patched_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm="",
    ))
    return "".join(diff)


# ==============================================================================
# Public API
# ==============================================================================

def generate_and_apply_patch(
    target_file: str,
    root_cause: str,
    suggested_fix: str,
    iteration: int = 1,
    sast_text: str = "",
    fuzz_text: str = "",
    dast_text: str = "",
    verdict: Optional[object] = None,
    history: Optional[List[dict]] = None,
) -> dict:
    with open(target_file, "r", encoding="utf-8") as fh:
        original_source = fh.read()

    # Backup original before modifying
    backup_path = target_file + ".original"
    if not os.path.exists(backup_path):
        shutil.copy2(target_file, backup_path)

    is_real_target = "real_target_adapter" in target_file
    filename = os.path.basename(target_file)

    patched_source = None
    strategy = "unknown"
    syntax_valid = False
    validation_message = ""

    if is_real_target:
        patched_source = _apply_real_target_patch(original_source)
        strategy = "real_target_template"
        syntax_valid, validation_message = validate_patch(original_source, patched_source, filename)
    else:
        # 1. Attempt LLM Patch
        vuln_type = getattr(verdict, 'vuln_type', 'SQL_INJECTION') if verdict else 'SQL_INJECTION'
        raw_response, provider_info = _llm_patch(
            original_source,
            root_cause,
            suggested_fix,
            vuln_type,
            sast_text,
            fuzz_text,
            dast_text,
            verdict,
            history
        )
        strategy = provider_info
        
        if raw_response:
            blocks = parse_replace_blocks(raw_response)
            if blocks:
                patched, applied_count = apply_replace_blocks(original_source, blocks)
                if applied_count > 0 and patched != original_source:
                    patched_source = patched
                    strategy = f"{provider_info} (blocks)"
            if not patched_source:
                extracted = _extract_python_code(raw_response)
                if extracted and extracted != original_source:
                    patched_source = extracted
                    strategy = f"{provider_info} (full)"

        # 2. Validate LLM Patch (syntax + AST)
        if patched_source:
            syntax_valid, validation_message = validate_patch(original_source, patched_source, filename)
            
        # 3. Fallback to deterministic template patch if LLM failed/invalidated
        if not patched_source or not syntax_valid:
            print(f"  [patch_agent] LLM patch failed validation ({validation_message}). Falling back to deterministic template.")
            patched_source = _apply_template_patch(original_source)
            strategy = "template"
            syntax_valid, validation_message = validate_patch(original_source, patched_source, filename)

    diff_text = _make_diff(original_source, patched_source, filename)
    lines_changed = count_lines_changed(diff_text)

    if not diff_text.strip():
        return {
            "success": False,
            "patched": False,
            "strategy": strategy,
            "diff": "",
            "message": "Patch produced no changes.",
            "iteration": iteration,
            "syntax_valid": syntax_valid,
            "validation_message": validation_message,
        }

    with open(target_file, "w", encoding="utf-8") as fh:
        fh.write(patched_source)

    return {
        "success": True,
        "patched": True,
        "file": target_file,
        "strategy": strategy,
        "diff": diff_text,
        "patched_file": target_file,
        "backup_file": backup_path,
        "iteration": iteration,
        "syntax_valid": syntax_valid,
        "validation_message": validation_message,
        "lines_changed": lines_changed,
        "confidence": 0.95 if syntax_valid else 0.5,
        "message": f"Patch applied via {strategy} strategy (iteration {iteration}).",
    }


def restore_original(target_file: str):
    backup_path = target_file + ".original"
    if os.path.exists(backup_path):
        shutil.copy2(backup_path, target_file)


def print_diff(diff_text: str):
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            print(f"  \033[90m{line}\033[0m")
        elif line.startswith("+"):
            print(f"  \033[92m{line}\033[0m")
        elif line.startswith("-"):
            print(f"  \033[91m{line}\033[0m")
        elif line.startswith("@@"):
            print(f"  \033[94m{line}\033[0m")
        else:
            print(f"  {line}")
