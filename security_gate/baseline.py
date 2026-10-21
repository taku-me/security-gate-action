"""baseline: 既存の違反の指紋。設計: docs/security-gate-design.md §3.6。

指揮役の裁定(2026-10-20): 段 1 を warn にするとユーザーの指示「ローカル LLM でも同じチェックを通さないと git push でエラーが出る」が
1 週間以上満たされない。既存の違反は repo ごとの `.security-gate-baseline.json` に指紋で入れ、**baseline に無い error は今日から block** にする。

指紋 = sha256(規則 id + path + 正規化した該当行)。行番号は入れないので、上に行を足してもずれない。
repo 単位の規則(行が無いもの)は 規則 id + path。
baseline は件数を出すだけ。増やす変更は Claude Code の PreToolUse(③)が ask で止め、ato は関門として守る。段 2 で減らす。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

BASELINE_FILE = ".security-gate-baseline.json"
_WS_RE = re.compile(r"\s+")
REPO_LEVEL_PREFIXES = ("web.no-", "deps.no-lockfile", "deps.vulnerable", "secret.env-file")


def normalize_line(text: str) -> str:
    return _WS_RE.sub(" ", text.strip())


def fingerprint(rule: str, path: str, line_text: Optional[str]) -> str:
    body = normalize_line(line_text) if line_text is not None else ""
    return hashlib.sha256(f"{rule}\n{path}\n{body}".encode("utf-8")).hexdigest()[:24]


def line_for(rule: str, lines: List[str], line_no: int) -> Optional[str]:
    """指紋に使う行。repo 単位の規則は行を持たない(None)。"""
    if rule.startswith(REPO_LEVEL_PREFIXES):
        return None
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def load(root: Path) -> Tuple[Set[str], List[str]]:
    """(指紋の集合, 読めなかった理由)。無ければ空。"""
    path = root / BASELINE_FILE
    if not path.is_file():
        return set(), []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return set(), [f"{BASELINE_FILE} を読めない: {e.__class__.__name__}: {e}"]
    rows = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return set(), [f"{BASELINE_FILE}: findings の配列が無い"]
    fps: Set[str] = set()
    problems: List[str] = []
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict) or not isinstance(r.get("fp"), str):
            problems.append(f"{BASELINE_FILE}: {i} 件目に fp が無い")
            continue
        fps.add(r["fp"])
    return fps, problems


def build(findings: List[Dict[str, Any]], today: str, note: str = "") -> Dict[str, Any]:
    """全体スキャンの error から baseline を作る(warn は入れない)。"""
    rows = []
    seen: Set[str] = set()
    for f in findings:
        if f.get("level") != "error" or not f.get("fp") or f["fp"] in seen:
            continue
        seen.add(f["fp"])
        rows.append({"rule": f["rule"], "path": f["path"], "fp": f["fp"], "hint": f.get("message", "")[:80]})
    rows.sort(key=lambda r: (r["rule"], r["path"], r["fp"]))
    return {"created": today, "note": note or "既存の違反の指紋。段 2 で減らす。増やす変更はユーザーの承認が要る(docs/security-gate-design.md §3.6)",
            "count": len(rows), "findings": rows}
