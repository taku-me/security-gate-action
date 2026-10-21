"""security-gate の共通の型。設計: docs/security-gate-design.md §3。Python 3.9 で動く(tomllib・match を使わない)。"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set

ERROR = "error"
WARN = "warn"
LEVELS = (ERROR, WARN)

# 秘密らしい名前(変数・環境変数の名前に含まれる語)
SECRET_NAME_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|webhook|private[_-]?key|signature)")
# 秘密らしく見えるが違う名前(数・型・名前の語)
NOT_SECRET_NAME_RE = re.compile(
    r"(?i)(token_type|tokeniz|_tokens\b|tokens?_(count|used|total|limit|per|in|out)|num_tokens|max_tokens|total_tokens|"
    r"prompt_tokens|completion_tokens|input_tokens|output_tokens|token_count|token_limit|token_budget|"
    r"keyword|key_?name|key_?path|key_?type|key_?id|key_?code|keyframe|keyboard|keypress|hotkey|primary_key|foreign_key|"
    r"_key_?s\b|_len\b|_count\b|_field|_header|_file|_path|_name|_url|_prefix|_suffix|_label|_mode|_kind|_env|_var|_type|_id\b|"
    r"_tokens?_|_cookie|_param|_query|_arg\b|_source|_dir\b|_cache|_store|_kwarg|"
    r"password_?(field|input|label|prompt|hash_algo|min|max|rules?|policy)|secret_?(name|path|file|id)|"
    r"token_?(name|path|file|url|endpoint|header|field|expires?|expiry|ttl|age))"
)
# 見本・環境から読む形の値(秘密ではない)
PLACEHOLDER_RE = re.compile(
    r"(?i)(\$\{|\$[A-Z_]|\{\{|<[^>]*>|^\.\.\.|xxx|example|your[-_ ]|changeme|change_me|dummy|placeholder|redacted|"
    r"\*\*\*|^none$|^null$|^true$|^false$|os\.environ|process\.env|getenv|secret\(|__|^\s*$)"
)
# == で比べてはいけない名前(認証に使う秘密。LLM の token(語)とは区別する)
COMPARE_SECRET_RE = re.compile(
    r"(?i)(api_?key|apikey|secret|password|passwd|signature|hmac|csrf|otp|"
    r"(auth|access|admin|bearer|session|api|refresh|expected|provided|given|supplied|incoming|client|server|"
    r"webhook|master|root|stored|saved|valid|real|user|login|reset|verify|verification|invite|share|magic)_?token"
    r"|_token$)"
)
TEST_PATH_RE = re.compile(r"(^|/)(tests?|spec|specs|fixtures?|__tests__|testdata|_test)(/|$)|_test\.[a-z]+$|\.test\.|\.spec\.|(^|/)test_[^/]*$|(^|/)conftest\.py$")

CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".sh", ".bash", ".zsh", ".rb", ".go", ".rs",
            ".php", ".java", ".kt", ".swift", ".html", ".htm", ".yml", ".yaml", ".toml", ".json", ".jsonl", ".ini",
            ".cfg", ".conf", ".env", ".txt", ".md", ".jinja", ".j2", ".tmpl", ".plist", ".service", ".xml", ".css"}
PY_EXT = {".py"}
JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue"}
SH_EXT = {".sh", ".bash", ".zsh"}
MARKUP_EXT = {".html", ".htm", ".vue", ".jinja", ".j2", ".tmpl", ".jsx", ".tsx"}
CONFIG_EXT = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".json", ".plist", ".service", ".env"}
SKIP_DIR_RE = re.compile(r"(^|/)(node_modules|\.venv|venv|\.git|dist|build|\.next|__pycache__|\.mypy_cache|\.ruff_cache|"
                         r"site-packages|\.tox|\.cache|vendor|third_party)(/|$)")
SKIP_FILE_RE = re.compile(r"(\.min\.(js|css)$|\.map$|\.lock$|package-lock\.json$|pnpm-lock\.yaml$|yarn\.lock$|"
                          r"\.(png|jpe?g|gif|webp|svg|ico|pdf|zip|gz|tar|woff2?|ttf|otf|mp[34]|wav|mov|bin|pyc|so|dylib)$)")
MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class Finding:
    level: str
    rule: str
    path: str
    line: int
    message: str

    def key(self) -> str:
        return f"{self.rule}|{self.path}|{self.line}"


@dataclass
class SourceFile:
    """検査の対象の 1 ファイル。text は読めた時だけ。"""
    path: str  # repo の根からの相対パス(/ 区切り)
    text: str
    lines: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.lines:
            self.lines = self.text.splitlines()

    @property
    def ext(self) -> str:
        return Path(self.path).suffix.lower()

    @property
    def name(self) -> str:
        return Path(self.path).name

    @property
    def is_test(self) -> bool:
        return TEST_PATH_RE.search(self.path) is not None

    def tree(self):
        """Python の AST(1 回だけ parse する。読めなければ None)。"""
        if not hasattr(self, "_tree"):
            import ast
            try:
                object.__setattr__(self, "_tree", ast.parse(self.text))
            except (SyntaxError, ValueError):
                object.__setattr__(self, "_tree", None)
        return self._tree


@dataclass
class Context:
    root: Path
    files: List[SourceFile]  # 今回見るファイル(差分、または全体)
    all_paths: List[str]  # repo の追跡される全ファイル(repo 単位の規則用)
    today: str  # YYYY-MM-DD
    extended: bool = False  # 外の道具(pip-audit・npm audit・zizmor)を流すか
    lint: bool = True  # linter(ruff・shellcheck・eslint・actionlint)を、あれば流すか
    network_timeout: float = 30.0
    notes: List[str] = field(default_factory=list)  # 検査できなかったことなど
    lock_paths: Optional[List[str]] = None  # 拡張の依存の監査で見る lockfile(None なら all_paths から探す)
    reader: Optional[Callable[[str], Optional[str]]] = None  # commit の中身を読む(pre-push)。None なら作業ツリー
    _read_cache: Dict[str, Optional[str]] = field(default_factory=dict)

    def read(self, rel: str) -> Optional[str]:
        """repo の中のファイルを読む(repo 単位の規則用)。読めない・大きい・二進なら None。"""
        if rel in self._read_cache:
            return self._read_cache[rel]
        text = self.reader(rel) if self.reader is not None else read_text(self.root / rel)
        self._read_cache[rel] = text
        return text


FileRule = Callable[[SourceFile, Context], List[Finding]]
RepoRule = Callable[[Context], List[Finding]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    level: str
    description: str
    file_rule: Optional[FileRule] = None
    repo_rule: Optional[RepoRule] = None
    extended: bool = False  # 外の道具と網が要る(依存の監査)
    lint: bool = False  # 道具があれば流す(無ければ note)。差分のファイルだけを見る


def read_text(path: Path) -> Optional[str]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def wanted(rel: str) -> bool:
    """検査の対象にする相対パスか。"""
    if SKIP_DIR_RE.search(rel) or SKIP_FILE_RE.search(rel):
        return False
    name = os.path.basename(rel)
    ext = os.path.splitext(name)[1].lower()
    if name.startswith(".env") or name in ("Dockerfile", "Containerfile") or name.startswith("Dockerfile."):
        return True
    if ext in CODE_EXT:
        return True
    return ext == "" and ("/" not in rel or rel.startswith((".github/", "bin/", "scripts/", "ops/")))


def is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//", "*", "/*", "<!--", "--", ";", "rem "))


def line_no(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def tokens_in(names: Sequence[str], text: str) -> Set[str]:
    return {n for n in names if n in text}
