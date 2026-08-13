import ast
import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SASTFinding:
    file: str
    line: int
    col: int
    severity: str                               
    rule_id: str
    description: str
    snippet: str
    confidence: str                             


                                                                                
                        
                                                                                

class SQLInjectionVisitor(ast.NodeVisitor):


    EXEC_METHODS = {"execute", "executemany", "executescript"}
    SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "JOIN")

    def __init__(self, source_lines: List[str]):
        self.findings: List[dict] = []
        self.source_lines = source_lines
                                                                         
                                                                                             
        self._var_scopes: dict = {}                                    
        self._var_map: dict = {}                                      

                                                                                

    def collect_assignments(self, tree: ast.AST):


                                       
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._var_map[target.id] = node.value
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.value:
                    self._var_map[node.target.id] = node.value

                                        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = {}
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for t in child.targets:
                            if isinstance(t, ast.Name):
                                scope[t.id] = child.value
                    elif isinstance(child, ast.AnnAssign):
                        if isinstance(child.target, ast.Name) and child.value:
                            scope[child.target.id] = child.value
                                                                            
                fn_key = f"_fn_{node.lineno}"
                for var, val in scope.items():
                    if var not in self._var_scopes:
                        self._var_scopes[var] = []
                    self._var_scopes[var].append((fn_key, val))

    def _resolve_in_context(self, node: ast.AST, call_lineno: int, depth: int = 0) -> list:


        if depth > 3:
            return [node]
        if not isinstance(node, ast.Name):
            return [node]
        name = node.id
        candidates = []
                                               
        if name in self._var_scopes:
            for (fn_key, val) in self._var_scopes[name]:
                candidates.extend(self._resolve_in_context(val, call_lineno, depth + 1))
                           
        if name in self._var_map:
            candidates.extend(self._resolve_in_context(self._var_map[name], call_lineno, depth + 1))
        return candidates if candidates else [node]


                                                                               

    def _resolve(self, node: ast.AST, depth: int = 0) -> ast.AST:

        if depth > 3:
            return node
        if isinstance(node, ast.Name) and node.id in self._var_map:
            return self._resolve(self._var_map[node.id], depth + 1)
        return node

    def _snippet(self, node: ast.AST) -> str:
        line = node.lineno - 1
        if 0 <= line < len(self.source_lines):
            return self.source_lines[line].strip()
        return "<unknown>"

    def _is_sql(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return any(kw in node.value.upper() for kw in self.SQL_KEYWORDS)
        return False

    def _has_dynamic(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                return True
        return False

    def _emit(self, node: ast.AST, rule: str, desc: str):
        self.findings.append({
            "line": node.lineno,
            "col": node.col_offset,
            "rule_id": rule,
            "description": desc,
            "snippet": self._snippet(node),
            "severity": "HIGH",
            "confidence": "HIGH",
        })

                                                                                

    def _check_expr(self, expr: ast.AST, call_node: ast.AST, func_name: str, depth: int = 0):
        if depth > 5:
            return

                                                     
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left_sql  = self._is_sql(expr.left)
            right_dyn = self._has_dynamic(expr.right)
            right_sql = self._is_sql(expr.right)
            left_dyn  = self._has_dynamic(expr.left)

            if left_sql and right_dyn:
                self._emit(call_node, "SQLI-CONCAT",
                    f"SQL query built via string concatenation passed to {func_name}(). "
                    "User-controlled input may reach DB without parameterization.")
                return
            if right_sql and left_dyn:
                self._emit(call_node, "SQLI-CONCAT",
                    f"SQL query built via string concatenation passed to {func_name}(). "
                    "User-controlled input may reach DB without parameterization.")
                return
                                                      
            self._check_expr(expr.left,  call_node, func_name, depth + 1)
            self._check_expr(expr.right, call_node, func_name, depth + 1)

                                          
        elif isinstance(expr, ast.JoinedStr):
            has_sql = has_var = False
            for v in expr.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    if any(kw in v.value.upper() for kw in self.SQL_KEYWORDS):
                        has_sql = True
                if isinstance(v, ast.FormattedValue):
                    has_var = True
            if has_sql and has_var:
                self._emit(call_node, "SQLI-FSTRING",
                    f"SQL query uses f-string interpolation in {func_name}(). "
                    "Variables inside f-strings are NOT parameterized.")

                                         
        elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
            if self._is_sql(expr.left):
                self._emit(call_node, "SQLI-PERCENT-FORMAT",
                    f"SQL query uses %% formatting in {func_name}(). "
                    "Use parameterized queries instead.")

                                                
        elif isinstance(expr, ast.Call):
            if (isinstance(expr.func, ast.Attribute)
                    and expr.func.attr == "format"
                    and self._is_sql(expr.func.value)):
                self._emit(call_node, "SQLI-FORMAT-METHOD",
                    f"SQL query uses .format() in {func_name}(). "
                    "Use parameterized queries instead.")

                                                                                

    def visit_Call(self, node: ast.Call):
        func_name: Optional[str] = None
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in self.EXEC_METHODS and node.args:
            raw_arg = node.args[0]
                                                                             
            candidates = self._resolve_in_context(raw_arg, node.lineno)
            seen = set()
            for candidate in candidates:
                cid = id(candidate)
                if cid not in seen:
                    seen.add(cid)
                    self._check_expr(candidate, node, func_name)
                                                                         
            if id(raw_arg) not in seen:
                self._check_expr(raw_arg, node, func_name)

        self.generic_visit(node)


                                                                                
            
                                                                                

def scan_file(filepath: str) -> List[SASTFinding]:

    with open(filepath, "r", encoding="utf-8") as fh:
        source = fh.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [SASTFinding(
            file=filepath, line=0, col=0,
            severity="ERROR", rule_id="PARSE-ERROR",
            description=f"Could not parse file: {exc}",
            snippet="", confidence="HIGH",
        )]

    lines = source.splitlines()
    visitor = SQLInjectionVisitor(lines)
                                                             
    visitor.collect_assignments(tree)
                                                
    visitor.visit(tree)

    findings = []
    for f in visitor.findings:
        findings.append(SASTFinding(
            file=filepath,
            line=f["line"],
            col=f["col"],
            severity=f["severity"],
            rule_id=f["rule_id"],
            description=f["description"],
            snippet=f["snippet"],
            confidence=f["confidence"],
        ))
    return findings


def scan_directory(dirpath: str) -> List[SASTFinding]:

    all_findings: List[SASTFinding] = []
    for root, _, files in os.walk(dirpath):
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                all_findings.extend(scan_file(fpath))
    return all_findings


def format_findings(findings: List[SASTFinding]) -> str:
    if not findings:
        return "  ✓ No SAST findings."
    lines = []
    for f in findings:
        lines.append(
            f"  [{f.severity}] {f.rule_id} @ {os.path.basename(f.file)}:{f.line}\n"
            f"    {f.description}\n"
            f"    snippet: {f.snippet}"
        )
    return "\n".join(lines)


                                                                                
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "target_app"
    findings = scan_directory(target)
    print(f"SAST scan complete — {len(findings)} finding(s)\n")
    print(format_findings(findings))
