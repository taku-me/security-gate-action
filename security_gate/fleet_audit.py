#!/usr/bin/env python3
"""全 repo に security-gate(②)が入っているかを照らす。設計: docs/security-gate-design.md §4。

  GH_TOKEN=… python3 security_gate/fleet_audit.py            # 表(markdown)を出す。足りない repo があれば終了コード 1
  GH_TOKEN=… python3 security_gate/fleet_audit.py --json

見るもの(repo ごと): caller の workflow があり fleet-skills の action を呼び template と一致するか / .security-gate.toml の mode と
[[allow]] の数 / baseline の件数 / 既定の枝の protection に security-gate が required か / 最新の run の結果。
表を出すだけ(書き込みの PAT は作らない。指揮役の裁定 2026-10-20。無い repo は security-watch の追跡 issue に出る)。
標準ライブラリの urllib だけ。token は GH_TOKEN か GITHUB_TOKEN(読み取り)。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from security_gate import allow as allow_mod  # noqa: E402

API = "https://api.github.com"
OWNER = "taku-me"
CALLER_PATH = ".github/workflows/security-gate.yml"
CALLER_USES = "taku-me/fleet-skills/security-gate@security-gate-action"
# 公開 repo は非公開の fleet-skills の action を呼べないので、公開の写しを呼ぶ(templates/caller-public.yml)
CALLER_USES_PUBLIC = "taku-me/security-gate-action/security-gate@main"
CHECK_NAME = "security-gate"
TEMPLATES = Path(__file__).resolve().parent / "templates"


class GitHub:
    def __init__(self, token: str) -> None:
        self.token = token

    def call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, ok404: bool = False) -> Any:
        url = path if path.startswith("http") else API + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "fleet-skills security-gate audit"})
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 404 and ok404:
                return None
            raise RuntimeError(f"{method} {path}: HTTP {e.code} {e.read()[:200]!r}") from e

    def paged(self, path: str) -> List[Any]:
        out: List[Any] = []
        page = 1
        while True:
            sep = "&" if "?" in path else "?"
            chunk = self.call("GET", f"{path}{sep}per_page=100&page={page}")
            if not chunk:
                break
            out += chunk
            if len(chunk) < 100:
                break
            page += 1
        return out


def _file(gh: GitHub, repo: str, path: str) -> Optional[str]:
    data = gh.call("GET", f"/repos/{repo}/contents/{urllib.parse.quote(path)}", ok404=True)
    if not data or data.get("encoding") != "base64":
        return None
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def _normalized(text: str) -> str:
    return "\n".join(line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))


def audit_repo(gh: GitHub, repo: Dict[str, Any]) -> Dict[str, Any]:
    name = repo["full_name"]
    default = repo.get("default_branch") or "main"
    row: Dict[str, Any] = {"repo": name, "archived": bool(repo.get("archived")), "fork": bool(repo.get("fork")),
                           "empty": repo.get("size") == 0, "default_branch": default,
                           "caller": False, "caller_ok": False, "mode": None, "allows": None, "baseline": None, "required": False,
                           "protection": None, "last_run": None, "problems": []}
    if row["archived"] or row["fork"] or row["empty"]:
        return row  # 対象外(archived・fork・空の repo)
    caller = _file(gh, name, CALLER_PATH)
    row["caller"] = caller is not None
    public = repo.get("private") is False
    uses, template = (CALLER_USES_PUBLIC, "caller-public.yml") if public else (CALLER_USES, "caller.yml")
    row["caller_ok"] = caller is not None and uses in caller
    if not row["caller_ok"]:
        row["problems"].append("caller が無い" if caller is None else f"caller が {uses} を呼んでいない")
    elif name != "taku-me/fleet-skills" and _normalized(caller) != _normalized((TEMPLATES / template).read_text(encoding="utf-8")):
        row["caller_ok"] = False
        row["problems"].append(f"caller が templates/{template} と違う(骨抜きの疑い。反証 §9 #9)")
    toml_text = _file(gh, name, allow_mod.ALLOW_FILE)
    if toml_text is not None:
        try:
            data = allow_mod.parse_subset(toml_text)
            row["mode"] = (data.get("gate") or {}).get("mode")
            row["allows"] = len(data.get("allow") or [])
        except allow_mod.AllowError as e:
            row["problems"].append(f"{allow_mod.ALLOW_FILE} を読めない: {e}")
    try:
        prot = gh.call("GET", f"/repos/{name}/branches/{default}/protection", ok404=True)
    except RuntimeError as e:
        prot = None
        if "403" in str(e):
            row["protection"] = "plan/権限で読めない(Free の非公開 repo か token に administration: read が無い)"
        else:
            row["problems"].append(f"protection を読めない: {str(e)[:80]}")
    contexts: List[str] = []
    if prot and prot.get("required_status_checks"):
        contexts = [c for c in prot["required_status_checks"].get("contexts", [])]
        contexts += [c.get("context") for c in prot["required_status_checks"].get("checks", []) if c.get("context")]
    row["required"] = CHECK_NAME in contexts
    if not row["required"] and not row.get("protection"):
        row["problems"].append("branch protection で required でない")
    runs = gh.call("GET", f"/repos/{name}/actions/workflows/security-gate.yml/runs?per_page=1", ok404=True)
    if runs and runs.get("workflow_runs"):
        run = runs["workflow_runs"][0]
        row["last_run"] = f"{run.get('conclusion') or run.get('status')} {run.get('created_at', '')[:10]}"
        if run.get("conclusion") not in (None, "success"):
            row["problems"].append(f"最新の run が {run.get('conclusion')}")
    return row


def render(rows: List[Dict[str, Any]]) -> str:
    lines = ["| repo | caller | mode | allow | baseline | required | 最新の run | 問題 |", "|---|---|---|---|---|---|---|---|"]

    def skip(r: Dict[str, Any]) -> bool:
        return bool(r.get("archived") or r.get("fork") or r.get("empty"))

    for r in rows:
        if skip(r):
            continue
        required = "✓" if r["required"] else ("plan" if r.get("protection") else "✗")
        lines.append(f"| {r['repo']} | {'✓' if r['caller_ok'] else '✗'} | {r['mode'] or '-'} | "
                     f"{'-' if r['allows'] is None else r['allows']} | {'-' if r.get('baseline') is None else r['baseline']} | {required} | "
                     f"{r['last_run'] or '-'} | {'; '.join(r['problems'])} |")
    active = [r for r in rows if not skip(r)]
    ok = [r for r in active if not r["problems"]]
    lines.append("")
    lines.append(f"repo {len(active)}(archived・fork・空の {len(rows) - len(active)} は対象外)/ 問題なし {len(ok)} / "
                 f"caller あり {sum(1 for r in active if r['caller_ok'])} / required {sum(1 for r in active if r['required'])} / "
                 f"allow の合計 {sum(r['allows'] or 0 for r in active)} / baseline の合計 {sum(r.get('baseline') or 0 for r in active)}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", help="repo 名(カンマ区切り)に絞る")
    ap.add_argument("--summary-file", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    args = ap.parse_args(argv)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GH_TOKEN か GITHUB_TOKEN が要る", file=sys.stderr)
        return 2
    gh = GitHub(token)
    repos = gh.paged("/user/repos?affiliation=owner&sort=full_name")
    only = set(args.only.split(",")) if args.only else None
    rows: List[Dict[str, Any]] = []
    for repo in repos:
        if only and repo["full_name"] not in only and repo["name"] not in only:
            continue
        try:
            row = audit_repo(gh, repo)
        except RuntimeError as e:  # 1 repo の失敗で全体を止めない(反証 §9(運用)#4)
            row = {"repo": repo["full_name"], "archived": False, "fork": False, "empty": False, "caller_ok": False,
                   "mode": None, "allows": None, "baseline": None, "required": False, "protection": None, "last_run": None,
                   "problems": [f"読めない: {str(e)[:100]}"]}
        rows.append(row)
    if args.json:
        print(json.dumps({"rows": rows}, ensure_ascii=False))
    else:
        print(render(rows))
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as fh:
            fh.write("## security-gate の照合\n\n" + render(rows) + "\n")
    return 1 if any(r["problems"] for r in rows if not (r.get("archived") or r.get("fork") or r.get("empty"))) else 0


if __name__ == "__main__":
    sys.exit(main())
