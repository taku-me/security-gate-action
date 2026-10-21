"""secret.*: 秘密の直書き。設計 §1 の 2 と 8。

gitleaks が見逃した Discord の webhook と Google の `AIza` を含め、形(正規表現)で見る。
値そのものは出力に出さない(先頭 4 文字と長さだけ)。
"""

from __future__ import annotations

import ast
import re
from typing import List, Optional

from ..model import (COMPARE_SECRET_RE, ERROR, NOT_SECRET_NAME_RE, PLACEHOLDER_RE, PY_EXT, SECRET_NAME_RE, Context,
                     Finding, SourceFile, is_comment_line, line_no)

# (名前, 正規表現, 試験ファイルでも見るか)
PATTERNS = [
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"), True),
    ("discord-webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{6,}/[\w\-]{20,}"), True),
    ("discord-bot-token", re.compile(r"\b[MN][A-Za-z\d_\-]{23,}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,}\b"), True),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,}"), True),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), True),
    ("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b"), True),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"), True),
    ("openai-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b"), True),
    ("google-oauth-token", re.compile(r"\bya29\.[0-9A-Za-z_\-]{30,}"), True),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), True),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), False),
    ("bearer", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9_\-.=]{20,})"), False),
]
ASSIGN_RE = re.compile(
    r"(?i)(?P<name>[A-Za-z_][A-Za-z0-9_\-]*)\s*(?:[:=]|=>)\s*(?P<q>[\"'])(?P<value>(?:(?!(?P=q)).){8,}?)(?P=q)"
)
ENV_NAME_RE = re.compile(r"(?i)(?:^|[^A-Za-z0-9_])(?P<name>[A-Z][A-Z0-9_]*)=(?P<value>[^\s#\"']{8,})$")
ENV_FILE_RE = re.compile(r"^\.env(\..+)?$")
ENV_FILE_OK = (".example", ".sample", ".template", ".dist", ".schema")
PATHLIKE_RE = re.compile(r"^(~|\.{1,2}/|/|[A-Za-z]:\\|https?://[^@]*$|file:|s3://|gs://)")


def _hint(value: str) -> str:
    return f"{value[:4]}…({len(value)} 文字)"


def _placeholder(value: str) -> bool:
    if PLACEHOLDER_RE.search(value):
        return True
    return len(set(value)) <= 2  # xxxxxxxx・00000000


def _finding(f: SourceFile, line: int, kind: str, value: str) -> Finding:
    return Finding(ERROR, "secret.pattern", f.path, line, f"{kind} の形の値 {_hint(value)}。環境変数か秘密の置き場から読む")


def check_patterns(f: SourceFile, ctx: Context) -> List[Finding]:
    out: List[Finding] = []
    prose = f.ext in (".md", ".txt", ".rst")
    for kind, pattern, in_tests in PATTERNS:
        if f.is_test and not in_tests:
            continue
        if prose and kind in ("private-key", "bearer", "jwt"):
            continue  # 文章の中の形の説明(ヘッダの行だけなど)は見ない
        for m in pattern.finditer(f.text):
            value = m.group(1) if m.groups() else m.group(0)
            if kind in ("bearer", "jwt") and _placeholder(value):
                continue
            if kind == "openai-key" and value.startswith("sk-ant-"):
                continue
            out.append(_finding(f, line_no(f.text, m.start()), kind, value))
    return out


def _secret_name(name: str) -> bool:
    return SECRET_NAME_RE.search(name) is not None and NOT_SECRET_NAME_RE.search(name) is None


def _compare_secret_name(name: str) -> bool:
    return COMPARE_SECRET_RE.search(name) is not None and NOT_SECRET_NAME_RE.search(name) is None


def check_assignment(f: SourceFile, ctx: Context) -> List[Finding]:
    """秘密らしい名前に 8 文字以上のリテラルを代入。試験ファイルは見ない。"""
    if f.is_test or f.ext in (".md", ".txt", ".jsonl"):
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        for m in ASSIGN_RE.finditer(line):
            name, value = m.group("name"), m.group("value")
            if not _secret_name(name) or _placeholder(value) or " " in value.strip():
                continue
            if PATHLIKE_RE.match(value):
                continue  # パス・URL(秘密を含む URL は secret.pattern で拾う)
            if f.ext in (".yml", ".yaml") and name.lower() in ("secret", "token") and value.startswith("${{"):
                continue
            out.append(Finding(ERROR, "secret.assignment", f.path, i,
                               f"{name} に値 {_hint(value)} を直書き。環境変数か秘密の置き場から読む"))
            break
    return out


def check_env_file(f: SourceFile, ctx: Context) -> List[Finding]:
    name = f.name
    if not ENV_FILE_RE.match(name) or name.endswith(ENV_FILE_OK):
        return []
    has_value = any(ENV_NAME_RE.search(line) for line in f.lines if not is_comment_line(line))
    if not has_value:
        return []
    return [Finding(ERROR, "secret.env-file", f.path, 1, f"{name} が追跡されている。.gitignore に入れ、git rm --cached で外す")]


# --- secret.fallback-default(Python は AST、JS は正規表現) ---------------------------------------

JS_FALLBACK_RE = re.compile(
    r"process\.env\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\|\||\?\?)\s*[\"'`](?P<value>[^\"'`]+)[\"'`]"
)
JS_FALLBACK_BRACKET_RE = re.compile(
    r"process\.env\[\s*[\"'](?P<name>[A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]\s*(?:\|\||\?\?)\s*[\"'`](?P<value>[^\"'`]+)[\"'`]"
)


def _env_get_call(node: ast.AST) -> Optional[str]:
    """os.environ.get("X", …)・os.getenv("X", …) なら X を返す。"""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    names = (("environ", "get"), ("os", "getenv"), ("getenv",))
    ok = False
    if isinstance(func, ast.Attribute) and func.attr in ("get", "getenv"):
        base = func.value
        if func.attr == "get" and isinstance(base, (ast.Attribute, ast.Name)) and (
                getattr(base, "attr", None) == "environ" or getattr(base, "id", None) == "environ"):
            ok = True
        if func.attr == "getenv" and isinstance(base, ast.Name) and base.id == "os":
            ok = True
    elif isinstance(func, ast.Name) and func.id == "getenv":
        ok = True
    del names
    if not ok or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _nonempty_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip() != "" \
        and not _placeholder(node.value)


def check_fallback_py(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in PY_EXT or f.is_test:
        return []
    tree = f.tree()
    if tree is None:
        return []
    out: List[Finding] = []
    for node in ast.walk(tree):
        name = _env_get_call(node)
        if name is not None and _secret_name(name):
            call = node  # type: ignore[assignment]
            default = call.args[1] if len(call.args) > 1 else next(
                (k.value for k in call.keywords if k.arg == "default"), None)
            if default is not None and _nonempty_str(default):
                out.append(Finding(ERROR, "secret.fallback-default", f.path, node.lineno,
                                   f"{name} の既定値が固定の文字列。無ければ落ちる形(os.environ[\"{name}\"])にする"))
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) and len(node.values) >= 2:
            left = node.values[0]
            env_name = _env_get_call(left)
            if env_name is None and isinstance(left, ast.Subscript):
                base = left.value
                if isinstance(base, (ast.Attribute, ast.Name)) and (
                        getattr(base, "attr", None) == "environ" or getattr(base, "id", None) == "environ"):
                    sl = left.slice
                    if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                        env_name = sl.value
            if env_name is not None and _secret_name(env_name) and _nonempty_str(node.values[1]):
                out.append(Finding(ERROR, "secret.fallback-default", f.path, node.lineno,
                                   f"{env_name} が無い時に固定の文字列へ落ちる(or)。無ければ落ちる形にする"))
    return out


def check_fallback_js(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx") or f.is_test:
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        for pat in (JS_FALLBACK_RE, JS_FALLBACK_BRACKET_RE):
            m = pat.search(line)
            if m and _secret_name(m.group("name")) and not _placeholder(m.group("value")):
                out.append(Finding(ERROR, "secret.fallback-default", f.path, i,
                                   f"process.env.{m.group('name')} の既定値が固定の文字列。無ければ落ちる形にする"))
    return out


# --- secret.timing-compare ----------------------------------------------------------------------

JS_COMPARE_RE = re.compile(
    r"(?P<left>[A-Za-z_$][\w$.\[\]'\"]*)\s*(?P<op>[!=]==?)\s*(?P<right>[A-Za-z_$][\w$.\[\]'\"]*|[\"'`][^\"'`]*[\"'`])"
)
_NOT_VALUE_RE = re.compile(r"^(null|undefined|true|false|\"\"|''|``|0)$")


def _name_text(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
        return _name_text(node.value)
    if isinstance(node, ast.Call):
        return _name_text(node.func)
    return None


def _trivial(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and (node.value is None or isinstance(node.value, (bool, int, float))
                                               or node.value == "")


def check_timing_py(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in PY_EXT or f.is_test:
        return []
    tree = f.tree()
    if tree is None:
        return []
    out: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            continue
        left, right = node.left, node.comparators[0]
        if _trivial(left) or _trivial(right):
            continue
        names = [n for n in (_name_text(left), _name_text(right)) if n]
        if any(_compare_secret_name(n) for n in names):
            out.append(Finding(ERROR, "secret.timing-compare", f.path, node.lineno,
                               f"{' / '.join(names)} を == で比べている。hmac.compare_digest を使う"))
    return out


def check_timing_js(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx") or f.is_test:
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        for m in JS_COMPARE_RE.finditer(line):
            left, right = m.group("left"), m.group("right")
            if _NOT_VALUE_RE.match(right) or _NOT_VALUE_RE.match(left):
                continue
            names = [left.split(".")[-1], right.split(".")[-1]]
            if any(_compare_secret_name(n) for n in names) and not right.startswith(("'", '"', "`")):
                out.append(Finding(ERROR, "secret.timing-compare", f.path, i,
                                   f"{left} {m.group('op')} {right}: crypto.timingSafeEqual を使う"))
                break
    return out
