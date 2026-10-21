"""lint.*: 各言語の linter を中央の設定(security_gate/lint/)で流す。設計 §1.2。

ruff(flake8-bandit S・flake8-async)・shellcheck・eslint(eslint-plugin-security)・actionlint。
道具が無ければ流さず、`lint.unavailable` の note を 1 つ出す(止めない。CI の action は道具を入れてから流すので、そこで揃う)。
規則の id は `lint.<道具>.<規則>`。許可は同じ仕組み(行の gate-allow・.security-gate.toml)。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ..model import ERROR, JS_EXT, PY_EXT, SH_EXT, WARN, Context, Finding

LINT_DIR = Path(__file__).resolve().parent.parent / "lint"
# S のうち error にするもの(それ以外の S・ASYNC は warn)
RUFF_ERROR = {"S102", "S104", "S105", "S106", "S107", "S301", "S302", "S307", "S306", "S308", "S312", "S321",
              "S501", "S502", "S503", "S504", "S505", "S506", "S602", "S604", "S605", "S608", "S609", "S701", "S702"}
TIMEOUT = 120.0


def _run(argv: List[str], cwd: Path, env: Optional[Dict[str, str]] = None) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=TIMEOUT, check=False,
                              env=dict(os.environ, **(env or {})))
    except (OSError, subprocess.TimeoutExpired):
        return None


def _note_missing(ctx: Context, tool: str, what: str) -> None:
    msg = f"lint.unavailable: {tool} が無いので {what} を流していない(CI では流れる)"
    if msg not in ctx.notes:
        ctx.notes.append(msg)


def _ruff(ctx: Context, paths: List[str]) -> List[Finding]:
    if not paths:
        return []
    if not shutil.which("ruff"):
        _note_missing(ctx, "ruff", "Python の S/ASYNC")
        return []
    p = _run(["ruff", "check", "--config", str(LINT_DIR / "ruff.toml"), "--output-format", "json",
              "--exit-zero", "--no-cache", "--", *paths], ctx.root)
    if p is None or not p.stdout.strip():
        if p is not None and p.returncode not in (0, 1):
            ctx.notes.append(f"lint.ruff を流せなかった({(p.stderr or '').strip()[:200]})")
        return []
    try:
        rows = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    out: List[Finding] = []
    for r in rows:
        code = r.get("code") or ""
        rel = os.path.relpath(r.get("filename", ""), str(ctx.root)).replace(os.sep, "/")
        level = ERROR if code in RUFF_ERROR else WARN
        out.append(Finding(level, f"lint.ruff.{code}", rel, int((r.get("location") or {}).get("row") or 1),
                           f"{r.get('message', '')}(ruff {code})"))
    return out


def _shellcheck(ctx: Context, paths: List[str]) -> List[Finding]:
    if not paths:
        return []
    if not shutil.which("shellcheck"):
        _note_missing(ctx, "shellcheck", "shell の検査")
        return []
    p = _run(["shellcheck", "--format", "json1", "--severity", "warning", "--", *paths], ctx.root,
             env={"SHELLCHECKRC": str(LINT_DIR / "shellcheckrc")})
    if p is None or not p.stdout.strip():
        return []
    try:
        rows = json.loads(p.stdout).get("comments", [])
    except (json.JSONDecodeError, AttributeError):
        return []
    out: List[Finding] = []
    for r in rows:
        level = ERROR if r.get("level") == "error" else WARN
        rel = str(r.get("file", "")).replace(os.sep, "/")
        out.append(Finding(level, f"lint.shellcheck.SC{r.get('code')}", rel, int(r.get("line") or 1),
                           f"{r.get('message', '')}(shellcheck SC{r.get('code')})"))
    return out


def _eslint(ctx: Context, paths: List[str]) -> List[Finding]:
    if not paths:
        return []
    exe = shutil.which("eslint") or (str(LINT_DIR / "node_modules" / ".bin" / "eslint")
                                     if (LINT_DIR / "node_modules" / ".bin" / "eslint").exists() else None)
    if not exe or not (LINT_DIR / "node_modules" / "eslint-plugin-security").exists():
        _note_missing(ctx, "eslint + eslint-plugin-security", "JS/TS の検査")
        return []
    p = _run([exe, "--no-config-lookup", "--config", str(LINT_DIR / "eslint.config.mjs"), "--format", "json",
              "--no-error-on-unmatched-pattern", "--", *[str(ctx.root / x) for x in paths]], ctx.root)
    if p is None or not p.stdout.strip():
        if p is not None and p.returncode not in (0, 1):
            ctx.notes.append(f"lint.eslint を流せなかった({(p.stderr or '').strip()[:200]})")
        return []
    try:
        rows = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    out: List[Finding] = []
    for f in rows:
        rel = os.path.relpath(f.get("filePath", ""), str(ctx.root)).replace(os.sep, "/")
        for m in f.get("messages", []):
            rule = m.get("ruleId") or "parse"
            if rule == "parse" and m.get("fatal"):
                continue  # 文法を読めないファイル(TS の型など)は見ない
            level = ERROR if m.get("severity") == 2 else WARN
            out.append(Finding(level, f"lint.eslint.{rule.replace('/', '.')}", rel, int(m.get("line") or 1),
                               f"{m.get('message', '')}(eslint {rule})"))
    return out


def _actionlint(ctx: Context, paths: List[str]) -> List[Finding]:
    if not paths:
        return []
    if not shutil.which("actionlint"):
        _note_missing(ctx, "actionlint", "workflow の文法")
        return []
    p = _run(["actionlint", "-format", "{{json .}}", "-no-color", "--", *paths], ctx.root)
    if p is None or not p.stdout.strip():
        return []
    try:
        rows = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    out: List[Finding] = []
    for r in rows:
        kind = r.get("kind") or "syntax"
        out.append(Finding(ERROR, f"lint.actionlint.{kind}", str(r.get("filepath", "")), int(r.get("line") or 1),
                           f"{r.get('message', '')}(actionlint {kind})"))
    return out


def _zizmor(ctx: Context, paths: List[str]) -> List[Finding]:
    """zizmor は --offline(token 無しの online の監査は 401 で "no audit was performed" になる。反証 §9(運用)#3)。"""
    if not paths:
        return []
    if not shutil.which("zizmor"):
        _note_missing(ctx, "zizmor", "workflow の監査")
        return []
    p = _run(["zizmor", "--offline", "--format", "json", "--no-progress", "--", *paths], ctx.root)
    if p is None or not p.stdout.strip():
        return []
    try:
        rows = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    out: List[Finding] = []
    for r in rows:
        sev = str(r.get("determinations", {}).get("severity", "")).lower()
        level = ERROR if sev in ("high", "critical") else WARN
        rel, line = paths[0], 1
        try:
            loc = (r.get("locations") or [{}])[0]
            sym = loc.get("symbolic") or {}
            key = sym.get("key") or {}
            rel = str((key.get("Local") or {}).get("given_path") or rel) if isinstance(key, dict) else str(key)
            start = ((loc.get("concrete") or {}).get("location") or {}).get("start_point")
            if isinstance(start, (list, tuple)) and start:
                line = int(start[0]) + 1
            elif isinstance(start, dict):
                line = int(start.get("row", 0)) + 1
        except (TypeError, ValueError, AttributeError):
            pass
        if r.get("ident") == "unpinned-uses" and any(s in json.dumps(r) for s in ("taku-me/fleet-skills/", "taku-me/security-gate-action/")):
            continue  # 艦隊の正典は @main で呼ぶ(設計 §2.2。actions.unpinned と同じ例外)
        out.append(Finding(level, f"lint.zizmor.{r.get('ident', 'audit')}", rel, line,
                           f"{r.get('desc', '')}({sev})"))
    return out


def check_lint(ctx: Context) -> List[Finding]:
    py = [f.path for f in ctx.files if f.ext in PY_EXT]
    sh = [f.path for f in ctx.files if f.ext in SH_EXT or (f.ext == "" and f.lines and f.lines[0].startswith("#!") and "sh" in f.lines[0])]
    js = [f.path for f in ctx.files if f.ext in JS_EXT and f.ext != ".vue"]
    wf = [f.path for f in ctx.files if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", f.path)]
    out: List[Finding] = []
    for tool, fn, targets in (("ruff", _ruff, py), ("shellcheck", _shellcheck, sh), ("eslint", _eslint, js),
                              ("actionlint", _actionlint, wf), ("zizmor", _zizmor, wf)):
        try:
            out += fn(ctx, targets)
        except Exception as e:  # noqa: BLE001 — 1 つの道具の失敗で他の道具を止めない。落ちたことは note に出す
            ctx.notes.append(f"lint.{tool} が落ちた({e.__class__.__name__}: {e})")
    return out
