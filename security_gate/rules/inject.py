"""inject.*: shell・ssh・git の引数・argparse の注入。設計 §1 の 5。Python は ast、JS/TS と sh は正規表現。"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional

from ..model import ERROR, JS_EXT, PY_EXT, SH_EXT, WARN, Context, Finding, SourceFile, is_comment_line

SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
GIT_SUBS = {"clone", "fetch", "pull", "push", "checkout", "switch", "ls-remote", "log", "show", "branch", "rev-parse",
            "diff", "merge", "rebase", "reset", "rm", "add", "tag", "submodule", "archive", "cat-file", "blame"}
GIT_REMOTE_SUBS = {"clone", "fetch", "pull", "push", "ls-remote", "submodule", "remote", "archive"}  # upload-pack などの注入は error
GIT_GLOBAL_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
JS_EXEC_RE = re.compile(r"\b(?:child_process\.)?(execSync|exec|spawnSync|spawn|execFileSync|execFile)\s*\(\s*(?P<arg>[^,)]*)")
JS_SHELL_TRUE_RE = re.compile(r"\bshell\s*:\s*true\b")
SH_EVAL_RE = re.compile(r"(^|[;&|]\s*)eval\s+\"?\$")
SH_BASH_C_RE = re.compile(r"\b(ba|z|)sh\s+-c\s+\"[^\"]*\$[{(A-Za-z_]")
SH_SSH_RE = re.compile(r"\bssh\s+(?:-\S+\s+(?:\S+\s+)?)*[\w.@:\-]+\s+\"[^\"]*\$[{(A-Za-z_]")
SH_GIT_RE = re.compile(r"\bgit\s+(?:-C\s+\S+\s+)?(" + "|".join(sorted(GIT_SUBS)) + r")\s+(?P<rest>[^|;&\n]*)")


def _is_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_literal(e) for e in node.elts)
    return False


def _is_dynamic_string(node: ast.AST) -> bool:
    """f-string・連結・.format・% のどれかで、shlex.quote / shlex.join を通していないもの。"""
    dynamic = (isinstance(node, ast.JoinedStr)
               or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
               or (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "join")))
    if not dynamic:
        return False
    try:
        text = ast.unparse(node)
    except Exception:  # noqa: BLE001
        return True
    return "quote(" not in text and "shlex.join(" not in text


def _aliases(tree: ast.AST) -> Dict[str, str]:
    """import の別名 → 正式な名前(`import subprocess as sp` → sp: subprocess、`from os import system as go` → go: os.system)。"""
    out: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _func_name(node: ast.Call, aliases: Optional[Dict[str, str]] = None) -> str:
    aliases = aliases or {}
    func = node.func
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        base = func.value
        prefix = base.id if isinstance(base, ast.Name) else (base.attr if isinstance(base, ast.Attribute) else "")
        prefix = aliases.get(prefix, prefix)
        return f"{prefix}.{func.attr}" if prefix else func.attr
    return ""


def _kw(node: ast.Call, name: str) -> Optional[ast.AST]:
    for k in node.keywords:
        if k.arg == name:
            return k.value
    return None


def _shell_true(node: ast.Call) -> bool:
    v = _kw(node, "shell")
    return isinstance(v, ast.Constant) and v.value is True


def _list_consts(node: ast.AST) -> Optional[List[Optional[str]]]:
    """リスト/タプルのリテラルなら、要素を文字列(非リテラルは None)で返す。"""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    out: List[Optional[str]] = []
    for e in node.elts:
        out.append(e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None)
    return out


def _argv_problems(node: ast.AST, f: SourceFile) -> List[Finding]:
    """argv の配列(subprocess の 1 つ目)を見る: ssh の f-string、git の `--` 無し、`--opt` の直後の変数。"""
    consts = _list_consts(node)
    if not consts or not isinstance(node, (ast.List, ast.Tuple)):
        return []
    elts = node.elts
    out: List[Finding] = []
    head = consts[0] or ""
    if head == "ssh" or head.endswith("/ssh"):
        for e in elts[1:]:
            if _is_dynamic_string(e):
                out.append(Finding(ERROR, "inject.ssh-unquoted", f.path, node.lineno,
                                   "ssh の遠隔コマンドに f-string/連結。shlex.quote で各引数を囲むか、引数を分ける"))
                break
    if head == "git" or head.endswith("/git"):
        i = 1
        while i < len(elts) and consts[i] is not None and consts[i].startswith("-"):  # type: ignore[union-attr]
            i += 2 if consts[i] in GIT_GLOBAL_WITH_VALUE else 1
        while i < len(elts) and consts[i] is None:  # -C <var> の値を飛ばす
            i += 1
        if i < len(elts) and consts[i] in GIT_SUBS:
            rest = elts[i + 1:]
            rest_consts = consts[i + 1:]
            has_dashdash = "--" in rest_consts
            dynamic = [e for e in rest if isinstance(e, (ast.Name, ast.Attribute, ast.Subscript))]
            if dynamic and not has_dashdash:
                level = ERROR if consts[i] in GIT_REMOTE_SUBS else WARN
                out.append(Finding(level, "inject.git-arg", f.path, node.lineno,
                                   f"git {consts[i]} の引数に変数。`--` で option と値を分けるか、値の形を確かめる"
                                   "(--upload-pack= のような option の注入)"))
    for prev, cur in zip(elts, elts[1:]):
        if isinstance(prev, ast.Constant) and isinstance(prev.value, str) and prev.value.startswith("--") \
                and "=" not in prev.value and isinstance(cur, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
            out.append(Finding(WARN, "inject.argv-unbound-value", f.path, node.lineno,
                               f"{prev.value} の値が別の要素。値が - で始まると option に化ける。{prev.value}=<値> の形にする"))
            break
    return out


def check_py(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in PY_EXT or f.is_test:
        return []
    tree = f.tree()
    if tree is None:
        return []
    out: List[Finding] = []
    aliases = _aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _func_name(node, aliases)
        short = name.split(".")[-1]
        first = node.args[0] if node.args else _kw(node, "args")
        if short in SUBPROCESS_FUNCS and (name.startswith("subprocess.") or "." not in name):
            if first is not None and _shell_true(node) and not _is_literal(first):
                out.append(Finding(ERROR, "inject.shell", f.path, node.lineno,
                                   f"{name}(…, shell=True) にリテラルでない文字列。配列で渡し shell=True を外す"))
            elif first is not None:
                out += _argv_problems(first, f)
        elif name in ("os.system", "os.popen", "commands.getoutput"):
            if first is not None and not _is_literal(first):
                out.append(Finding(ERROR, "inject.shell", f.path, node.lineno, f"{name} にリテラルでない文字列。subprocess の配列にする"))
        elif name in ("eval", "exec") and first is not None and not _is_literal(first):
            out.append(Finding(ERROR, "inject.shell", f.path, node.lineno, f"{name}() にリテラルでない値。ast.literal_eval か別の設計にする"))
    return out


def check_js(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in JS_EXT or f.is_test:
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        m = JS_EXEC_RE.search(line)
        if m:
            fn, arg = m.group(1), m.group("arg")
            if fn in ("execSync", "exec") and ("${" in arg or "+" in arg or re.match(r"^\s*[A-Za-z_$][\w$.]*\s*$", arg)):
                out.append(Finding(ERROR, "inject.shell", f.path, i,
                                   f"{fn}() に連結した文字列。execFileSync(cmd, [args]) にする"))
                continue
        if JS_SHELL_TRUE_RE.search(line) and ("spawn" in line or "exec" in line):
            out.append(Finding(ERROR, "inject.shell", f.path, i, "shell: true。配列で渡して shell を使わない"))
    return out


def check_sh(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in SH_EXT and not (f.ext == "" and f.text.startswith("#!") and "sh" in f.lines[0] if f.lines else False):
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        if SH_EVAL_RE.search(line):
            out.append(Finding(ERROR, "inject.shell", f.path, i, 'eval "$…"。配列と "$@" で渡す'))
        elif SH_BASH_C_RE.search(line):
            out.append(Finding(ERROR, "inject.shell", f.path, i, 'sh -c "…$var…"。引数として渡す(sh -c \'… "$1"\' _ "$var")'))
        elif SH_SSH_RE.search(line):
            out.append(Finding(ERROR, "inject.ssh-unquoted", f.path, i, 'ssh host "…$var…"。printf %q で quote する'))
        else:
            m = SH_GIT_RE.search(line)
            if m and re.search(r"(^|\s)\"?\$[{A-Za-z_]", m.group("rest")) and " -- " not in m.group("rest") \
                    and not m.group("rest").rstrip().endswith(" --"):
                out.append(Finding(WARN, "inject.git-arg", f.path, i, f"git {m.group(1)} の引数に変数。`--` で分ける"))
    return out
