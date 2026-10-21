"""deps.vulnerable(拡張): pip-audit・npm audit を呼ぶ。網と道具が要る。設計 §1 の 1、§2.1 の「速さ」。

道具が無い・網に届かない時は止めず、`deps.unchecked` の warn を 1 件出す(CI では道具を入れてから流すので、そこで止まる)。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import List, Optional, Tuple

from ..model import ERROR, WARN, Context, Finding

NPM_LEVELS = ("critical", "high")


def _run(argv: List[str], cwd: str, timeout: float, stdin: Optional[str] = None) -> Tuple[Optional[int], str, str]:
    try:
        p = subprocess.run(argv, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, "", f"{argv[0]} が {timeout:g} 秒で終わらない"
    except OSError as e:
        return None, "", f"{argv[0]} を起動できない: {e}"
    return p.returncode, p.stdout, p.stderr


def _unchecked(path: str, why: str) -> Finding:
    return Finding(WARN, "deps.unchecked", path, 1, f"依存の監査ができなかった({why})。CI で止まる")


def _pip_audit(ctx: Context, lock_rel: str, requirements_text: Optional[str], cwd: str) -> List[Finding]:
    if not shutil.which("pip-audit"):
        return [_unchecked(lock_rel, "pip-audit が無い")]
    argv = ["pip-audit", "--disable-pip", "--no-deps", "--format", "json", "--progress-spinner", "off", "-r"]
    argv.append("/dev/stdin" if requirements_text is not None else lock_rel.rsplit("/", 1)[-1])
    rc, out, err = _run(argv, cwd, ctx.network_timeout, stdin=requirements_text)
    if rc is None or (rc not in (0, 1)) or not out.strip():
        return [_unchecked(lock_rel, (err.strip().splitlines() or [f"終了コード {rc}"])[-1][:200])]
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return [_unchecked(lock_rel, "pip-audit の出力が JSON でない")]
    findings: List[Finding] = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            fix = ", ".join(v.get("fix_versions") or []) or "直す版なし"
            findings.append(Finding(ERROR, "deps.vulnerable", lock_rel, 1,
                                    f"{dep.get('name')} {dep.get('version')}: {v.get('id')}(直す版 {fix})|{v.get('id')}"))
    return findings


def _uv_export(ctx: Context, lock_rel: str, cwd: str) -> Tuple[Optional[str], Optional[str]]:
    if not shutil.which("uv"):
        return None, "uv が無い"
    rc, out, err = _run(["uv", "export", "--frozen", "--no-hashes", "--no-emit-project", "--all-extras", "--quiet"], cwd, 30)
    if rc != 0:
        rc, out, err = _run(["uv", "export", "--frozen", "--no-hashes", "--quiet"], cwd, 30)
    if rc != 0:
        return None, (err.strip().splitlines() or ["uv export が失敗"])[-1][:200]
    return out, None


def _npm_audit(ctx: Context, lock_rel: str, cwd: str) -> List[Finding]:
    if not shutil.which("npm"):
        return [_unchecked(lock_rel, "npm が無い")]
    rc, out, err = _run(["npm", "audit", "--package-lock-only", "--omit=dev", "--json"], cwd, ctx.network_timeout)
    if rc is None or not out.strip():
        return [_unchecked(lock_rel, (err.strip().splitlines() or [f"終了コード {rc}"])[-1][:200])]
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return [_unchecked(lock_rel, "npm audit の出力が JSON でない")]
    if "error" in data:
        return [_unchecked(lock_rel, str(data["error"].get("summary") or data["error"])[:200])]
    findings: List[Finding] = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        sev = v.get("severity")
        if sev not in NPM_LEVELS:
            continue
        ids = [via.get("url", "").rsplit("/", 1)[-1] for via in v.get("via", []) if isinstance(via, dict)]
        vid = ids[0] if ids else f"npm:{name}"
        fix = v.get("fixAvailable")
        fix_text = "直す版あり" if fix else "直す版なし"
        findings.append(Finding(ERROR, "deps.vulnerable", lock_rel, 1, f"{name} ({sev}, {fix_text}) {vid}|{vid}"))
    return findings


def check_deps(ctx: Context) -> List[Finding]:
    if not ctx.extended:
        return []
    out: List[Finding] = []
    paths = ctx.all_paths if ctx.lock_paths is None else ctx.lock_paths
    for rel in paths:
        if "node_modules/" in rel or "/.venv/" in rel:
            continue
        d, name = os.path.split(rel)
        cwd = str(ctx.root / d) if d else str(ctx.root)
        if name == "uv.lock":
            text, why = _uv_export(ctx, rel, cwd)
            if text is None:
                out.append(_unchecked(rel, why or "uv export"))
            else:
                out += _pip_audit(ctx, rel, text, cwd)
        elif name in ("requirements.txt", "requirements.lock") and not any(
                p.startswith(d + "/" if d else "") and p.endswith("uv.lock") and os.path.dirname(p) == d for p in ctx.all_paths):
            out += _pip_audit(ctx, rel, None, cwd)
        elif name == "package-lock.json":
            out += _npm_audit(ctx, rel, cwd)
    return out
