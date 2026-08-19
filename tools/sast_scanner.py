# THIS IS UPDATED TESTING VERSION

#run this code: 
#    1. use pyhton3 sast_scanner.py
#    2. use python3 sast_scanner.py --aggressive   >> for aggressive scan

#!/usr/bin/env python3
"""
Advanced Python SAST Scanner
Architectural improvements: Data-flow analysis, cycle-safe variable resolution,
taint tracking, interprocedural-aware scoping, external JSON configuration,
and dual-mode precision scanning (Proper vs. Aggressive).
"""

import ast
import os
import sys
import json
import re
import argparse
from dataclasses import dataclass
from typing import List, Dict, Optional, Set

# -------------------------------------------------------------------------
# CORE DATA MODELS
# -------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    line: int
    col: int
    severity: str
    rule_id: str
    description: str
    snippet: str
    confidence: str
    cwe: str = ""

@dataclass
class TrackedValue:
    value: str
    is_tainted: bool
    taint_source: Optional[str] = None

# -------------------------------------------------------------------------
# TAINT & DATA-FLOW ENGINE
# -------------------------------------------------------------------------

class Scope:
    def __init__(self, parent=None):
        self.parent: Optional['Scope'] = parent
        self.assignments: Dict[str, List[ast.AST]] = {}
        self.aliases: Dict[str, str] = {}
        self.functions: Dict[str, ast.FunctionDef] = {}

    def add_assignment(self, name: str, node: ast.AST):
        if name not in self.assignments:
            self.assignments[name] = []
        self.assignments[name].append(node)

    def get_assignments(self, name: str) -> List[ast.AST]:
        if name in self.assignments:
            return self.assignments[name]
        if self.parent:
            return self.parent.get_assignments(name)
        return []

    def add_alias(self, local_name: str, real_name: str):
        self.aliases[local_name] = real_name

    def resolve_alias(self, name: str) -> str:
        if name in self.aliases:
            return self.aliases[name]
        if self.parent:
            return self.parent.resolve_alias(name)
        return name

class SymbolTableBuilder(ast.NodeVisitor):
    def __init__(self):
        self.global_scope = Scope()
        self.current_scope = self.global_scope
        self.scopes: Dict[ast.AST, Scope] = {}

    def visit(self, node: ast.AST):
        self.scopes[node] = self.current_scope
        super().visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local_name = alias.asname if alias.asname else alias.name
            self.current_scope.add_alias(local_name, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            local_name = alias.asname if alias.asname else alias.name
            self.current_scope.add_alias(local_name, f"{module}.{alias.name}")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.current_scope.add_assignment(target.id, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if isinstance(node.target, ast.Name) and node.value:
            self.current_scope.add_assignment(node.target.id, node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.current_scope.functions[node.name] = node
        new_scope = Scope(parent=self.current_scope)
        for arg in node.args.args:
            new_scope.add_assignment(arg.arg, ast.Name(id=f"<ARG_{arg.arg}>", ctx=ast.Load()))
        prev_scope = self.current_scope
        self.current_scope = new_scope
        self.generic_visit(node)
        self.current_scope = prev_scope

class TaintEvaluator:
    def __init__(self, scope: Scope, taint_sources: Set[str]):
        self.scope = scope
        self.taint_sources = taint_sources
        self.visited = set()

    def evaluate(self, node: ast.AST) -> List[TrackedValue]:
        if id(node) in self.visited:
            return [TrackedValue("<CIRCULAR_REFERENCE>", False)]
        self.visited.add(id(node))
        try:
            results = self._eval_node(node)
            return results if results else [TrackedValue("<UNKNOWN>", False)]
        finally:
            self.visited.remove(id(node))

    def _eval_node(self, node: ast.AST) -> List[TrackedValue]:
        if isinstance(node, ast.Constant):
            return [TrackedValue(str(node.value), False)]
            
        elif isinstance(node, ast.Name):
            if any(ts in node.id for ts in self.taint_sources) or node.id.startswith("<ARG_"):
                return [TrackedValue(f"<{node.id}>", True, taint_source=node.id)]
            assignments = self.scope.get_assignments(node.id)
            if not assignments:
                return [TrackedValue(f"<{node.id}>", False)]
            return self.evaluate(assignments[-1])

        elif isinstance(node, ast.Attribute):
            full_name = self._get_attribute_name(node)
            is_tainted = any(ts in full_name for ts in self.taint_sources)
            return [TrackedValue(f"<{full_name}>", is_tainted, taint_source=full_name if is_tainted else None)]

        elif isinstance(node, ast.Subscript) or isinstance(node, ast.FormattedValue):
            return self.evaluate(node.value)

        elif isinstance(node, ast.JoinedStr):
            parts, is_tainted = [], False
            for val in node.values:
                evals = self.evaluate(val)
                if evals:
                    parts.append(evals[0].value)
                    if evals[0].is_tainted: is_tainted = True
            return [TrackedValue("".join(parts), is_tainted)]

        elif isinstance(node, ast.BoolOp):
            results = []
            for val in node.values:
                results.extend(self.evaluate(val))
            return results

        elif isinstance(node, ast.BinOp):
            lefts, rights, results = self.evaluate(node.left), self.evaluate(node.right), []
            if isinstance(node.op, ast.Add):
                for l in lefts:
                    for r in rights: results.append(TrackedValue(l.value + r.value, l.is_tainted or r.is_tainted))
            elif isinstance(node.op, ast.Mod):
                for l in lefts:
                    for r in rights: results.append(TrackedValue(l.value.replace("%s", r.value), l.is_tainted or r.is_tainted))
            else:
                return [TrackedValue("<BINOP>", False)]
            return results

        elif isinstance(node, ast.Call):
            func_name = self._get_attribute_name(node.func)
            is_tainted = any(ts in func_name for ts in self.taint_sources)
            if isinstance(node.func, ast.Attribute) and any(e.is_tainted for e in self.evaluate(node.func.value)):
                is_tainted = True
            if func_name.endswith('.format'):
                base_str_node = node.func.value if isinstance(node.func, ast.Attribute) else None
                if base_str_node:
                    base_eval = self.evaluate(base_str_node)[0]
                    if base_eval.is_tainted: is_tainted = True
                    for arg in node.args:
                        if self.evaluate(arg)[0].is_tainted: is_tainted = True
                    return [TrackedValue(base_eval.value, is_tainted)]
            for arg in node.args:
                if any(e.is_tainted for e in self.evaluate(arg)): is_tainted = True
            return [TrackedValue(f"<CALL_{func_name}>", is_tainted)]
            
        return [TrackedValue("<UNKNOWN_NODE>", False)]

    def _get_attribute_name(self, node) -> str:
        if isinstance(node, ast.Name): return node.id
        elif isinstance(node, ast.Attribute): return f"{self._get_attribute_name(node.value)}.{node.attr}"
        return ""

# -------------------------------------------------------------------------
# RULE ENGINE
# -------------------------------------------------------------------------

class Rule:
    def analyze(self, node: ast.AST, scope: Scope, filename: str, evaluator: TaintEvaluator, aggressive: bool) -> List[Finding]:
        raise NotImplementedError

class DynamicDataFlowRule(Rule):
    def __init__(self, config: dict):
        self.id = config.get("id", "GENERIC_000")
        self.title = config.get("title", "Generic Vulnerability")
        self.severity = config.get("severity", "MEDIUM")
        self.cwe = config.get("cwe", "")
        self.sinks = set(config.get("sinks", []))
        
        regex_pattern = config.get("regex")
        self.regex = re.compile(regex_pattern, re.IGNORECASE) if regex_pattern else None

    def analyze(self, node: ast.AST, scope: Scope, filename: str, evaluator: TaintEvaluator, aggressive: bool) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        func_name = ""
        if isinstance(node.func, ast.Name): func_name = node.func.id
        elif isinstance(node.func, ast.Attribute): func_name = node.func.attr
            
        real_func_name = scope.resolve_alias(func_name)
        
        # --- DUAL-MODE SINK MATCHING ---
        is_sink_match = False
        for sink in self.sinks:
            if aggressive:
                # Loose matching: Catches "runner" containing "run"
                if sink in real_func_name:
                    is_sink_match = True
                    break
            else:
                # Proper matching: Catches exact names ("execute") or module calls ("db.execute")
                if real_func_name == sink or real_func_name.endswith(f".{sink}"):
                    is_sink_match = True
                    break

        if not is_sink_match:
            return findings

        target_arg = None
        if node.args:
            target_arg = node.args[0]
        else:
            for kw in node.keywords:
                if kw.arg in ('sql', 'query', 'operation', 'script', 'command'):
                    target_arg = kw.value
                    break
                    
        if not target_arg: return findings

        evaluated_values = evaluator.evaluate(target_arg)

        for eval_val in evaluated_values:
            matches_regex = bool(self.regex.search(eval_val.value)) if self.regex else True
            is_pure_taint = eval_val.is_tainted and eval_val.value.startswith("<")
            
            if eval_val.is_tainted and (matches_regex or (is_pure_taint and not self.regex)):
                findings.append(Finding(
                    file=filename,
                    line=node.lineno,
                    col=node.col_offset,
                    severity=self.severity,
                    rule_id=self.id,
                    description=f"[{self.title}] Untrusted data flows into execution. Payload: '{eval_val.value[:50]}...'",
                    snippet=ast.unparse(node)[:200],
                    confidence="HIGH" if matches_regex else "MEDIUM",
                    cwe=self.cwe
                ))
                break

        return findings

# -------------------------------------------------------------------------
# ENGINE / ORCHESTRATOR
# -------------------------------------------------------------------------

class Scanner:
    def __init__(self, target_dir: str, config_path: str = "sast_config.json", aggressive: bool = False):
        self.target_dir = target_dir
        self.aggressive = aggressive
        self.rules: List[Rule] = []
        self.taint_sources: Set[str] = set()
        self.findings: List[Finding] = []
        self.diagnostics: List[str] = []
        
        self._load_config(config_path)

    def _load_config(self, config_path: str):
        default_config = {
            "taint_sources": ["request", "input", "environ", "argv", "os.environ", "sys.argv"],
            "rules": [{
                "id": "SQLI_001",
                "title": "SQL Injection",
                "severity": "HIGH",
                "cwe": "CWE-89",
                "sinks": ["execute", "executemany", "executescript", "run_query"],
                "regex": "^\\s*(SELECT|INSERT|UPDATE|DELETE|MERGE|UPSERT|REPLACE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|CALL|WITH)\\b"
            }]
        }
        
        config = default_config
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
            except Exception as e:
                self.diagnostics.append(f"Failed to load {config_path}, falling back to defaults. Error: {e}")
        
        self.taint_sources = set(config.get("taint_sources", []))
        for rule_cfg in config.get("rules", []):
            self.rules.append(DynamicDataFlowRule(rule_cfg))

    def scan(self):
        for root, dirs, files in os.walk(self.target_dir):
            if '.sastignore' in files:
                dirs[:] = []
                continue
                
            for file in files:
                if file.endswith('.py'):
                    self.analyze_file(os.path.join(root, file))

    def analyze_file(self, filepath: str):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
            
            sym_builder = SymbolTableBuilder()
            sym_builder.visit(tree)
            
            for node in ast.walk(tree):
                scope = sym_builder.scopes.get(node, sym_builder.global_scope)
                evaluator = TaintEvaluator(scope, self.taint_sources)
                
                for rule in self.rules:
                    # Pass the dual-mode flag down to the rule
                    self.findings.extend(rule.analyze(node, scope, filepath, evaluator, self.aggressive))
                    
        except SyntaxError as e:
            self.diagnostics.append(f"SyntaxError in {filepath}: {e}")
        except Exception as e:
            self.diagnostics.append(f"Unexpected error in {filepath}: {e}")

# -------------------------------------------------------------------------
# REPORTERS
# -------------------------------------------------------------------------

def format_findings(findings: List[Finding]) -> str:
    if not findings:
        return "  ✓ No SAST findings."
    lines = [f"SAST scan complete — {len(findings)} finding(s)\n"]
    for f in findings:
        lines.append(
            f"  [{f.severity}] {f.rule_id} @ {os.path.basename(f.file)}:{f.line}\n"
            f"    {f.description}\n"
            f"    snippet: {f.snippet}"
        )
    return "\n".join(lines)

def scan_file(filepath: str, config_path: Optional[str] = None, aggressive: bool = False) -> List[Finding]:
    if config_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, "sast_config.json")
    scanner = Scanner(os.path.dirname(filepath) or ".", config_path=config_path, aggressive=aggressive)
    scanner.analyze_file(filepath)
    return scanner.findings

def scan_directory(target_dir: str, config_path: Optional[str] = None, aggressive: bool = False) -> List[Finding]:
    if config_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, "sast_config.json")
    scanner = Scanner(target_dir, config_path=config_path, aggressive=aggressive)
    scanner.scan()
    return scanner.findings

def report_text(findings: List[Finding]):
    print(format_findings(findings))


def report_json(findings: List[Finding]):
    out = [{
        "file": f.file, "line": f.line, "col": f.col,
        "severity": f.severity, "rule_id": f.rule_id,
        "cwe": f.cwe, "description": f.description,
        "confidence": f.confidence, "snippet": f.snippet
    } for f in findings]
    print(json.dumps(out, indent=2))

def report_sarif(findings: List[Finding]):
    runs = {"tool": {"driver": {"name": "Advanced Python SAST", "rules": []}}, "results": []}
    for f in findings:
        runs["results"].append({
            "ruleId": f.rule_id,
            "level": "error" if f.severity == "HIGH" else "warning",
            "message": {"text": f.description},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": f.line, "startColumn": f.col + 1}
            }}]
        })
    sarif = {"version": "2.1.0", "$schema": "http://json.schemastore.org/sarif-2.1.0", "runs": [runs]}
    print(json.dumps(sarif, indent=2))

# -------------------------------------------------------------------------
# CLI ENTRYPOINT
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# CLI ENTRYPOINT
# -------------------------------------------------------------------------

def main():
    # 1. Get the absolute path of the directory containing this script (the 'tools' folder)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. Resolve the default target directory (Go up one level, then into 'target_app')
    default_target = os.path.normpath(os.path.join(script_dir, "..", "target_app"))
    
    # 3. Resolve the default config file (Right next to this script in the 'tools' folder)
    default_config = os.path.join(script_dir, "sast_config.json")

    parser = argparse.ArgumentParser(description="Advanced Python SAST Scanner")
    
    # Inject the dynamic paths as the defaults
    parser.add_argument("target_dir", nargs="?", default=default_target, help="Directory to scan")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format")
    parser.add_argument("--config", default=default_config, help="Path to JSON rule config")
    parser.add_argument("--aggressive", action="store_true", help="Enable heuristic substring matching (higher recall, higher false positives)")
    
    args = parser.parse_args()

    if not os.path.isdir(args.target_dir) and not os.path.isfile(args.target_dir):
        print(f"Error: Target '{args.target_dir}' does not exist.")
        sys.exit(1)

    scanner = Scanner(args.target_dir, args.config, args.aggressive)
    scanner.scan()

    if scanner.diagnostics:
        for diag in scanner.diagnostics:
            sys.stderr.write(f"[WARN] {diag}\n")

    if args.format == "text":
        report_text(scanner.findings)
    elif args.format == "json":
        report_json(scanner.findings)
    elif args.format == "sarif":
        report_sarif(scanner.findings)
        
    if any(f.severity == "HIGH" or f.severity == "CRITICAL" for f in scanner.findings):
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()