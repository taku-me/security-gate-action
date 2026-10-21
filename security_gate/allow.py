"""許可(誤検知の逃げ道)の読み取り。設計: docs/security-gate-design.md §3.4。

- 行の許可: 当たった行か直前の行の `gate-allow: <規則 id> <理由>`(理由は 10 文字以上)
- repo の許可: `.security-gate.toml` の `[gate]` と `[[allow]]`。tomllib が無い Python 3.9 でも読めるよう、
  `[table]`・`[[table]]`・`key = "文字列"` だけの小さな読み手を持つ。tomllib があればそれを使い、試験で両方が同じ結果を出すことを見る
"""

from __future__ import annotations

import datetime
import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # Python 3.10 以前
    tomllib = None  # type: ignore[assignment]

ALLOW_FILE = ".security-gate.toml"
MIN_REASON = 10
INLINE_RE = re.compile(r"gate-allow:\s*(?P<rule>[a-z][A-Za-z0-9._-]*)\s*(?P<reason>.*?)\s*(?:-->|\*/)?\s*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MODES = ("warn", "block")
REPO_LEVEL_RULES = ("web.", "deps.", "lint.unavailable")
MAX_GLOB_DAYS = 366


class AllowError(Exception):
    pass


@dataclass
class AllowEntry:
    rule: str
    path: Optional[str] = None  # fnmatch。無ければ repo 全体
    vuln_id: Optional[str] = None  # deps.vulnerable の脆弱性 id
    reason: str = ""
    expires: Optional[str] = None
    line: int = 0


@dataclass
class AllowConfig:
    mode: Optional[str] = None
    entries: List[AllowEntry] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)  # 読めた上での不備(理由が短いなど)


# --- toml の部分集合の読み手 ---------------------------------------------------------------

_KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$")


def _parse_value(raw: str, lineno: int) -> Any:
    raw = raw.strip()
    if raw.startswith(('"""', "\'\'\'")):
        raise AllowError(f"{lineno} 行目: 複数行の文字列は使えない")
    if raw.startswith('"'):
        end = raw.find('"', 1)
        while end != -1 and raw[end - 1] == "\\":
            end = raw.find('"', end + 1)
        if end == -1:
            raise AllowError(f"{lineno} 行目: 文字列が閉じていない")
        return raw[1:end].replace('\\"', '"').replace("\\\\", "\\")
    if raw.startswith("'"):
        end = raw.find("'", 1)
        if end == -1:
            raise AllowError(f"{lineno} 行目: 文字列が閉じていない")
        return raw[1:end]
    body = raw.split("#", 1)[0].strip()
    if body in ("true", "false"):
        return body == "true"
    if DATE_RE.match(body):
        return body
    if re.fullmatch(r"-?\d+", body):
        return int(body)
    raise AllowError(f"{lineno} 行目: 値は文字列・日付・整数・true/false だけ({body!r})")


def parse_subset(text: str) -> Dict[str, Any]:
    """`[gate]`・`[[allow]]`・`key = value` だけの toml を読む。tomllib と同じ形の dict を返す。"""
    data: Dict[str, Any] = {}
    current: Optional[Dict[str, Any]] = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[["):
            if not line.endswith("]]"):
                raise AllowError(f"{lineno} 行目: [[ が閉じていない")
            name = line[2:-2].strip()
            current = {}
            data.setdefault(name, []).append(current)
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                raise AllowError(f"{lineno} 行目: [ が閉じていない")
            name = line[1:-1].strip()
            current = data.setdefault(name, {})
            if not isinstance(current, dict):
                raise AllowError(f"{lineno} 行目: [{name}] は [[{name}]] と同時に使えない")
            continue
        m = _KEY_RE.match(line)
        if not m:
            raise AllowError(f"{lineno} 行目: key = value の形でない")
        if current is None:
            raise AllowError(f"{lineno} 行目: [gate] か [[allow]] の下に書く")
        key, value = m.group(1), m.group(2)
        if value.startswith(('"', "'")):
            # 文字列の後ろのコメントを許す
            current[key] = _parse_value(value, lineno)
        else:
            current[key] = _parse_value(value, lineno)
    return data


def _normalize(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()[:10]
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def _entry_from(row: Dict[str, Any], index: int, today: Optional[str] = None) -> Tuple[Optional[AllowEntry], Optional[str]]:
    label = f"[[allow]] {index}"
    rule = row.get("rule")
    if not isinstance(rule, str) or not re.fullmatch(r"[a-z][A-Za-z0-9._-]*", rule):
        return None, f"{label}: rule が無いか形が違う"
    reason = row.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < MIN_REASON:
        return None, f"{label}({rule}): reason は {MIN_REASON} 文字以上"
    expires = row.get("expires")
    if expires is not None and hasattr(expires, "isoformat"):
        expires = expires.isoformat()[:10]  # tomllib は日付を date 型にする
    if expires is not None and (not isinstance(expires, str) or not DATE_RE.match(expires)):
        return None, f"{label}({rule}): expires は YYYY-MM-DD"
    if rule == "deps.vulnerable" and not isinstance(row.get("id"), str):
        return None, f"{label}(deps.vulnerable): 脆弱性の id が要る"
    if expires is None:
        return None, f"{label}({rule}): expires が要る(許可は全部期限付き。最長 {MAX_GLOB_DAYS} 日。反証 §9 #11)"
    path = row.get("path")
    if path is not None and not isinstance(path, str):
        return None, f"{label}({rule}): path は文字列"
    repo_wide = path is None or path.strip() in ("*", "**", "", "./", ".")
    if repo_wide and not rule.startswith(REPO_LEVEL_RULES):
        return None, f"{label}({rule}): repo 全体の許可はできない(path にファイルか dir を書く。repo 単位の規則 {'/'.join(REPO_LEVEL_RULES)} だけは可)"
    if today is not None:
        try:
            delta = (datetime.date.fromisoformat(expires) - datetime.date.fromisoformat(today)).days
        except ValueError:
            delta = 0
        if delta > MAX_GLOB_DAYS:
            return None, f"{label}({rule}): expires は今日から {MAX_GLOB_DAYS} 日以内({expires})"
    return AllowEntry(rule=rule, path=path, vuln_id=row.get("id"), reason=reason.strip(), expires=expires), None


def load_config(root: Path, today: Optional[str] = None) -> AllowConfig:
    """`.security-gate.toml` を読む。無ければ空。壊れていれば problems に入れる(黙って無視しない)。"""
    cfg = AllowConfig()
    today = today or datetime.date.today().isoformat()
    path = root / ALLOW_FILE
    if not path.is_file():
        return cfg
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        cfg.problems.append(f"{ALLOW_FILE} を読めない: {e}")
        return cfg
    try:
        data = parse_subset(text)  # 3.9 のマシンと同じ読み手を正とする(反証 §9 #14: CI と手元で読み方が割れない)
    except AllowError as e:
        cfg.problems.append(f"{ALLOW_FILE}: {e}(この file は [gate]・[[allow]]・key = \"文字列\" / 日付 / 整数 だけ)")
        return cfg
    if tomllib is not None:
        try:
            full = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            cfg.problems.append(f"{ALLOW_FILE}: tomllib: {e}")
            return cfg
        if _normalize(full) != _normalize(data):
            cfg.problems.append(f"{ALLOW_FILE}: tomllib と 3.9 用の読み手で読み方が違う(複数行の文字列・配列・表を使わない)")
            return cfg
    for key in data:
        if key not in ("gate", "allow"):
            cfg.problems.append(f"{ALLOW_FILE}: 知らない鍵 {key!r}([gate] か [[allow]] の下に書く)")
    gate = data.get("gate", {})
    if isinstance(gate, dict) and "mode" in gate:
        if gate["mode"] in MODES:
            cfg.mode = gate["mode"]
        else:
            cfg.problems.append(f"{ALLOW_FILE}: [gate] mode は {'/'.join(MODES)} のどれか({gate['mode']!r})")
    rows = data.get("allow", [])
    if not isinstance(rows, list):
        cfg.problems.append(f"{ALLOW_FILE}: allow は [[allow]] の形で書く")
        return cfg
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            cfg.problems.append(f"[[allow]] {i}: 表でない")
            continue
        entry, problem = _entry_from(row, i, today)
        if problem:
            cfg.problems.append(problem)
        else:
            cfg.entries.append(entry)
    return cfg


def inline_allow(lines: List[str], line: int) -> Tuple[Optional[str], Optional[str], bool]:
    """当たった行(1 始まり)か直前の行の gate-allow を探す。(規則 id, 理由, 理由が足りない) を返す。"""
    for idx in (line - 1, line - 2):
        if 0 <= idx < len(lines):
            if idx == line - 2 and not lines[idx].lstrip().startswith(("#", "//", "<!--", "/*", "*", "--", ";")):
                continue  # 直前の行は、行全体がコメントの時だけ
            m = INLINE_RE.search(lines[idx])
            if m:
                reason = m.group("reason").strip()
                return m.group("rule"), reason, len(reason) < MIN_REASON
    return None, None, False


def matches(entry: AllowEntry, rule: str, path: str, vuln_id: Optional[str], today: str) -> Tuple[bool, bool]:
    """(当たる, 期限切れ)。"""
    if entry.rule != rule:
        return False, False
    if entry.path and not (fnmatch.fnmatch(path, entry.path) or path == entry.path
                           or (entry.path.endswith("/") and path.startswith(entry.path))):
        return False, False
    if rule == "deps.vulnerable" and entry.vuln_id != vuln_id:
        return False, False
    if entry.expires and entry.expires < today:
        return True, True
    return True, False
