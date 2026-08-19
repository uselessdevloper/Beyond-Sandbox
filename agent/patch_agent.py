import os
import re
import sys
import difflib
import subprocess
import shutil
from typing import Optional, Tuple


                                                                                
                                      
                                                                                

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

def _llm_patch(source: str, root_cause: str, suggested_fix: str) -> Tuple[Optional[str], str]:
    prompt = f"""You are a security engineer. Fix the SQL injection vulnerabilities in this Python Flask file.

ROOT CAUSE: {root_cause}

SUGGESTED FIX: {suggested_fix}

RULES:
1. Replace ALL string concatenation / f-string / %-format / .format() SQL patterns with parameterized queries using sqlite3's ? placeholder.
2. Do NOT change function names, routes, imports, or application logic.
3. Do NOT add new imports (sqlite3 is already imported).
4. Return ONLY the complete, fixed Python source file — no markdown, no explanation.

SOURCE FILE:
```python
{source}
```
"""
    raw_response, provider_info = query_llm(prompt, timeout=90.0)
    if not raw_response:
        return None, provider_info

    extracted = _extract_python_code(raw_response)
    if not extracted:
        return None, provider_info

    # Validate syntax
    try:
        compile(extracted, "<patch_check>", "exec")
    except SyntaxError as e:
        print(f"  [patch_agent] {provider_info} generated invalid Python syntax ({e}), using template patch.")
        return None, provider_info

    return extracted, provider_info


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
) -> dict:
    with open(target_file, "r", encoding="utf-8") as fh:
        original_source = fh.read()

    # Backup original before modifying
    backup_path = target_file + ".original"
    if not os.path.exists(backup_path):
        shutil.copy2(target_file, backup_path)

    is_real_target = "real_target_adapter" in target_file

    if is_real_target:
        patched_source = _apply_real_target_patch(original_source)
        strategy = "real_target_template"
    else:
        patched_source, provider_info = _llm_patch(original_source, root_cause, suggested_fix)
        strategy = provider_info
        if patched_source is None or patched_source.strip() == original_source.strip():
            patched_source = _apply_template_patch(original_source)
            strategy = "template"


    filename = os.path.basename(target_file)
    diff_text = _make_diff(original_source, patched_source, filename)

    if not diff_text.strip():
                                                                       
        return {
            "success": False,
            "strategy": strategy,
            "diff": "",
            "message": "Patch produced no changes.",
            "iteration": iteration,
        }

                        
    with open(target_file, "w", encoding="utf-8") as fh:
        fh.write(patched_source)

    return {
        "success": True,
        "strategy": strategy,
        "diff": diff_text,
        "patched_file": target_file,
        "backup_file": backup_path,
        "iteration": iteration,
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
