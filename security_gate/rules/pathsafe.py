"""path.*: パストラバーサル(関数の中の軽い taint)とプロキシのパス抜け。設計 §1 の 6。"""

from __future__ import annotations

import ast
import re
from typing import List, Optional, Set

from ..model import ERROR, JS_EXT, PY_EXT, Context, Finding, SourceFile, is_comment_line

ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "route", "api_route", "websocket", "options", "head"}
REQUEST_ATTRS = {"args", "form", "json", "files", "values", "query_params", "path_params", "headers", "cookies",
                 "data", "params", "body", "query", "url", "path", "full_path"}
SAFE_TYPES = {"int", "float", "bool", "UUID", "uuid.UUID", "Literal", "date", "datetime"}
SINKS = {"open", "Path", "send_file", "send_from_directory", "FileResponse", "os.path.join", "path.join",
         "os.remove", "os.unlink", "os.rename", "os.makedirs", "os.listdir", "os.scandir", "shutil.rmtree",
         "shutil.copy", "shutil.copyfile", "shutil.move", "shutil.copytree", "os.path.exists", "os.path.isfile",
         "aiofiles.open", "read_text", "write_text", "read_bytes", "write_bytes", "unlink", "mkdir", "rmdir", "rename"}
METHOD_SINKS = {"read_text", "write_text", "read_bytes", "write_bytes", "unlink", "mkdir", "rmdir", "rename"}
UNTAINT_CALLS = {"int", "float", "secure_filename", "basename", "os.path.basename", "uuid.UUID", "UUID", "len", "bool",
                 "hash", "sha256", "hashlib.sha256", "md5", "hashlib.md5", "abs", "round"}
GUARD_RE = re.compile(r"is_relative_to\(|relative_to\(|secure_filename\(|basename\(|fullmatch\(|re\.match\(|\.isalnum\(\)|"
                      r"isidentifier\(\)|fnmatch\(|commonpath\(|safe_join\(|\.isdigit\(\)|normpath\(|startswith\(str\(")
PROXY_WORDS_RE = re.compile(r"(?i)upstream|backend|target|base_url|proxy|forward")
JS_PATH_SINK_RE = re.compile(r"(path\.(join|resolve)|fs\.\w+|sendFile|res\.download|createReadStream|readFile\w*|"
                             r"writeFile\w*|unlink\w*)\s*\([^)]*req\.(params|query|body|path|url|headers)")
JS_GUARD_RE = re.compile(r"basename\(|normalize\(|startsWith\(|relative\(|sanitize|isSafe|validate")


def _dec_is_route(dec: ast.AST) -> bool:
    if isinstance(dec, ast.Call):
        dec = dec.func
    return isinstance(dec, ast.Attribute) and dec.attr in ROUTE_DECORATORS


def _annotation_safe(node: Optional[ast.AST]) -> bool:
    if node is None:
        return False
    try:
        text = ast.unparse(node)
    except Exception:  # noqa: BLE001
        return False
    return any(text == t or text.startswith(t + "[") or text.endswith("." + t) for t in SAFE_TYPES)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        try:
            return ast.unparse(func)
        except Exception:  # noqa: BLE001
            return func.attr
    return ""


def _names_in(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _from_request(node: ast.AST) -> bool:
    """request.args / request.form["x"] / await request.json() / req.query_params.get(...) のような値か。"""
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and n.attr in REQUEST_ATTRS and isinstance(n.value, ast.Name) \
                and n.value.id in ("request", "req", "self.request", "websocket"):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("get_json", "json", "form") \
                and isinstance(n.func.value, ast.Name) and n.func.value.id in ("request", "req"):
            return True
    return False


def _untainted(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node) in UNTAINT_CALLS


def _tainted_names(fn: ast.AST) -> Set[str]:
    tainted: Set[str] = set()
    if _is_route(fn):
        for arg in fn.args.args + fn.args.kwonlyargs + getattr(fn.args, "posonlyargs", []):  # type: ignore[attr-defined]
            if not _annotation_safe(arg.annotation) and arg.arg not in ("self", "cls", "request", "req", "websocket"):
                tainted.add(arg.arg)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            targets: List[ast.AST] = []
            value: Optional[ast.AST] = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                targets, value = [node.target], node.value
            elif isinstance(node, ast.NamedExpr):
                targets, value = [node.target], node.value
            elif isinstance(node, ast.For):
                targets, value = [node.target], node.iter
            elif isinstance(node, ast.comprehension):
                targets, value = [node.target], node.iter
            if value is None:
                continue
            if _untainted(value):
                continue
            if _from_request(value) or (_names_in(value) & tainted):
                for t in targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name) and n.id not in tainted:
                            tainted.add(n.id)
                            changed = True
    return tainted


def _is_route(fn: ast.AST) -> bool:
    return any(_dec_is_route(d) for d in getattr(fn, "decorator_list", []))


def _uses_request(fn: ast.AST) -> bool:
    return any(_from_request(n) for n in ast.walk(fn) if isinstance(n, (ast.Attribute, ast.Call)))


def check_py(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in PY_EXT or f.is_test:
        return []
    tree = f.tree()
    if tree is None:
        return []
    out: List[Finding] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not (_is_route(fn) or _uses_request(fn)):
            continue
        tainted = _tainted_names(fn)
        if not tainted:
            continue
        try:
            source = ast.unparse(fn)  # コメントと docstring 以外の、コードだけ(コメントの basename では守りにならない)
        except Exception:  # noqa: BLE001
            source = ""
        guarded = GUARD_RE.search(source) is not None
        seen: Set[int] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                short = name.split(".")[-1]
                if (name in SINKS or short in SINKS) and node.lineno not in seen:
                    if short in METHOD_SINKS and isinstance(node.func, ast.Attribute):
                        args = [node.func.value]  # p.write_text(...) は受け手 p がパス
                    elif short in ("open", "send_file", "FileResponse", "Path") or name == "aiofiles.open":
                        args = node.args[:1] + [k.value for k in node.keywords if k.arg in ("file", "path", "filename")]
                    else:
                        args = node.args + [k.value for k in node.keywords]
                    if any((_names_in(a) & tainted) or _from_request(a) for a in args if not _untainted(a)):
                        if not guarded:
                            out.append(Finding(ERROR, "path.traversal", f.path, node.lineno,
                                               f"{name}() に request 由来の値({', '.join(sorted(_names_in(node) & tainted) or ['request'])})。"
                                               "secure_filename か resolve()+is_relative_to で閉じる"))
                        seen.add(node.lineno)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and node.lineno not in seen:
                if (_names_in(node.right) & tainted) and not _untainted(node.right) and not guarded:
                    out.append(Finding(ERROR, "path.traversal", f.path, node.lineno,
                                       "Path / <request 由来の値>。resolve() して is_relative_to で閉じる"))
                    seen.add(node.lineno)
            elif isinstance(node, ast.JoinedStr) and node.lineno not in seen:
                has_url = any(isinstance(v, ast.Constant) and "://" in str(v.value) for v in node.values)
                names = _names_in(node)
                if (names & tainted) and (has_url or any(PROXY_WORDS_RE.search(n) for n in names)) \
                        and not ("normpath" in source and "unquote" in source):
                    out.append(Finding(ERROR, "path.proxy-unnormalized", f.path, node.lineno,
                                       "request の path を上流 URL に連結。unquote → posixpath.normpath で %2e%2e を潰し、"
                                       "許す prefix の下だけ通す"))
                    seen.add(node.lineno)
    return out


def check_js(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in JS_EXT or f.is_test:
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line) or JS_GUARD_RE.search(line):
            continue
        m = JS_PATH_SINK_RE.search(line)
        if m:
            out.append(Finding(ERROR, "path.traversal", f.path, i,
                               f"{m.group(1)} に req.{m.group(3)} をそのまま。path.basename か、resolve して startsWith(base) で閉じる"))
    return out
