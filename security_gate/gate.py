#!/usr/bin/env python3
"""security-gate の入口。設計: docs/security-gate-design.md。

  gate.py pre-push [remote] [url]   # git の pre-push hook から。stdin の ref の行を読み、push される差分だけ見る
  gate.py ci [--base <ref>]         # CI から。--base があれば merge-base からの差分、無ければ全体
  gate.py scan [path ...]           # 作業ツリーを全体(または指定のパス)で見る。数を測る時

共通: --root <repo> --mode warn|block --json --extended --no-extended --rules(規則の一覧)

出力は 1 件 1 行 `<level> <規則 id> <path>:<行> <説明>`、最後に合計。終了コードは block で error が 1 つ以上なら 1。
Python 3.9 の標準ライブラリだけで動く。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_gate import allow as allow_mod  # noqa: E402
from security_gate import baseline as baseline_mod  # noqa: E402
from security_gate.model import ERROR, WARN, Context, Finding, SourceFile, read_text, wanted  # noqa: E402
from security_gate.rules import RULE_LEVELS, RULES  # noqa: E402

DEFAULT_MODE = "block"  # 既定は block。既存の違反は baseline(§3.6)に入れ、baseline に無い error が push を止める。repo の toml は緩くできない
ZERO_SHA = "0" * 40
LOCK_NAMES = ("uv.lock", "requirements.txt", "requirements.lock", "package-lock.json", "poetry.lock")
REPO_RULE_TRIGGER = ("pyproject.toml", "package.json", "requirements", ".lock", "package-lock.json")
PREFIX = "security-gate:"


# --- git ----------------------------------------------------------------------------------------

def _git(root: Path, *args: str, check: bool = True) -> str:
    p = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()[:200]}")
    return p.stdout


def ls_files(root: Path, rev: Optional[str] = None) -> List[str]:
    if rev:
        out = _git(root, "ls-tree", "-r", "-z", "--name-only", rev)
    else:
        out = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return [p for p in out.split("\0") if p]


def changed_files(root: Path, base: str, head: str) -> List[str]:
    out = _git(root, "diff", "-z", "--name-only", "--diff-filter=ACMR", base, head)
    return [p for p in out.split("\0") if p]


class CommitReader:
    """`git cat-file --batch` 1 本で、commit の中のファイルを読む(pre-push は作業ツリーでなく push される中身を見る)。"""

    def __init__(self, root: Path, rev: str) -> None:
        self.rev = rev
        self.proc = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def read(self, rel: str) -> Optional[str]:
        assert self.proc.stdin and self.proc.stdout
        try:
            self.proc.stdin.write(f"{self.rev}:{rel}\n".encode())
            self.proc.stdin.flush()
            header = self.proc.stdout.readline().decode(errors="replace").strip()
        except (BrokenPipeError, OSError):
            return None
        parts = header.split()
        if len(parts) != 3 or parts[1] != "blob":
            return None
        size = int(parts[2])
        raw = self.proc.stdout.read(size)
        self.proc.stdout.read(1)  # 末尾の改行
        if size > 1_000_000 or b"\x00" in raw[:8192]:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()


def default_branch_ref(root: Path) -> Optional[str]:
    for cand in ("refs/remotes/origin/HEAD", "refs/remotes/origin/main", "refs/remotes/origin/master"):
        if subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "-q", cand], capture_output=True).returncode == 0:
            return cand
    return None


def pre_push_ranges(root: Path, stdin_lines: Iterable[str]) -> List[Tuple[str, str]]:
    """stdin の `<local ref> <local sha> <remote ref> <remote sha>` → [(base, head)]。削除の push は見ない。"""
    ranges: List[Tuple[str, str]] = []
    for line in stdin_lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        _lref, lsha, _rref, rsha = parts
        if lsha == ZERO_SHA:
            continue
        if any(h == lsha for _b, h in ranges):
            continue  # push --all で同じ commit を 2 度見ない
        # remote のどの ref にも無い commit が触ったファイル(反証 §9(運用)#7: rebase の後の push で、
        # main に入った他人の差分を自分のものとして見ない)。remote の ref が 1 つも無ければ全履歴 = 最初の push
        out = _git(root, "log", "--format=", "--name-only", "-z", "--diff-filter=ACMR", lsha, "--not", "--remotes", check=False)
        ranges.append(("__log__:" + "\0".join(p for p in out.split("\0") if p), lsha))
    return ranges


# --- 検査 ---------------------------------------------------------------------------------------

def load_sources(root: Path, paths: Iterable[str], reader=None) -> List[SourceFile]:
    files: List[SourceFile] = []
    for rel in paths:
        if not wanted(rel):
            continue
        text = reader(rel) if reader else read_text(root / rel)
        if text is None:
            continue
        files.append(SourceFile(rel, text))
    return files


def run_rules(ctx: Context, repo_rules: bool) -> List[Finding]:
    found: List[Finding] = []
    for rule in RULES:
        if rule.file_rule:
            for f in ctx.files:
                try:
                    found += rule.file_rule(f, ctx)
                except Exception as e:  # noqa: BLE001 — 1 つの規則が落ちても他は流す。落ちたことは出す
                    ctx.notes.append(f"{rule.rule_id} が {f.path} で落ちた({e.__class__.__name__}: {e})")
        if rule.repo_rule and (repo_rules or rule.extended or rule.lint):
            if rule.extended and not ctx.extended:
                continue
            if rule.lint and not ctx.lint:
                continue
            try:
                found += rule.repo_rule(ctx)
            except Exception as e:  # noqa: BLE001
                ctx.notes.append(f"{rule.rule_id} が落ちた({e.__class__.__name__}: {e})")
    seen: Set[str] = set()
    unique: List[Finding] = []
    for f in found:
        if f.key() not in seen:
            seen.add(f.key())
            unique.append(f)
    return unique


def apply_allows(findings: List[Finding], cfg: allow_mod.AllowConfig, files: Dict[str, SourceFile], today: str
                 ) -> Tuple[List[Finding], List[Tuple[Finding, str]]]:
    """(残る finding, 許可された (finding, 理由))。理由の無い行の許可は allow.no-reason の error に化ける。"""
    kept: List[Finding] = []
    allowed: List[Tuple[Finding, str]] = []
    for fd in findings:
        vuln_id = fd.message.rsplit("|", 1)[1] if fd.rule == "deps.vulnerable" and "|" in fd.message else None
        clean = Finding(fd.level, fd.rule, fd.path, fd.line, fd.message.rsplit("|", 1)[0] if vuln_id else fd.message)
        src = files.get(fd.path)
        rule, reason, short = allow_mod.inline_allow(src.lines, fd.line) if src else (None, None, False)
        if rule == fd.rule:
            if short:
                kept.append(Finding(ERROR, "allow.no-reason", fd.path, fd.line,
                                    f"gate-allow: {fd.rule} の理由が {allow_mod.MIN_REASON} 文字より短い。なぜ安全かを書く"))
            else:
                allowed.append((clean, reason or ""))
            continue
        hit = None
        expired = False
        for entry in cfg.entries:
            ok, exp = allow_mod.matches(entry, fd.rule, fd.path, vuln_id, today)
            if ok:
                hit, expired = entry, exp
                break
        if hit is not None and not expired:
            allowed.append((clean, hit.reason))
            continue
        kept.append(clean)
        if hit is not None and expired:
            kept.append(Finding(WARN, "allow.expired", fd.path, fd.line, f"{fd.rule} の許可が {hit.expires} で切れている"))
    return kept, allowed


def with_fingerprints(findings: List[Finding], files: Dict[str, SourceFile]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for f in findings:
        src = files.get(f.path)
        line_text = baseline_mod.line_for(f.rule, src.lines if src else [], f.line)
        rows.append(dict(f.__dict__, fp=baseline_mod.fingerprint(f.rule, f.path, line_text)))
    return rows


def summarize(findings: List[Dict[str, object]], allowed: List[Tuple[Finding, str]], files: int, elapsed: float, mode: str,
              notes: List[str], baselined: List[Dict[str, object]]) -> Dict[str, object]:
    errors = [f for f in findings if f["level"] == ERROR]
    warns = [f for f in findings if f["level"] == WARN]
    return {
        "mode": mode, "errors": len(errors), "warns": len(warns), "allowed": len(allowed), "baselined": len(baselined),
        "files": files, "seconds": round(elapsed, 2), "blocked": mode == "block" and bool(errors),
        "findings": findings,
        "baselined_findings": baselined,
        "allowed_findings": [dict(f.__dict__, reason=r) for f, r in allowed],
        "notes": notes,
        "by_rule": _count_by_rule(findings),
    }


def _count_by_rule(findings: List[Dict[str, object]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        out[str(f["rule"])] = out.get(str(f["rule"]), 0) + 1
    return dict(sorted(out.items()))


def print_report(summary: Dict[str, object], out=sys.stdout) -> None:
    for f in summary["findings"]:  # type: ignore[union-attr]
        print(f"{f['level']:5} {f['rule']:28} {f['path']}:{f['line']} {f['message']}", file=out)
    for f in summary["allowed_findings"]:  # type: ignore[union-attr]
        print(f"allow {f['rule']:28} {f['path']}:{f['line']} 許可({f['reason'][:60]})", file=out)
    for n in summary["notes"]:  # type: ignore[union-attr]
        print(f"note  {n}", file=out)
    print(f"{PREFIX} error {summary['errors']} / warn {summary['warns']} / baseline {summary['baselined']}(既存、止めない) / "
          f"allowed {summary['allowed']}(理由付き) / files {summary['files']} / {summary['seconds']}s / mode={summary['mode']}"
          + (" → push を止める" if summary["blocked"] else ""), file=out)


def check(root: Path, paths: List[str], all_paths: List[str], *, mode: Optional[str], extended: bool,
          reader=None, repo_rules: bool = True, lock_paths: Optional[List[str]] = None,
          network_timeout: float = 30.0, lint: bool = True) -> Dict[str, object]:
    started = time.monotonic()
    today = _dt.date.today().isoformat()
    cfg = allow_mod.load_config(root, today)
    # repo の toml は厳しくはできるが緩くはできない(反証 §9 #2)。--mode は呼ぶ側(試験・CI の入力)の明示なので従う
    effective_mode = mode or ("block" if "block" in (cfg.mode, DEFAULT_MODE) else "warn")
    files = load_sources(root, paths, reader)
    ctx = Context(root=root, files=files, all_paths=all_paths, today=today, extended=extended,
                  lock_paths=lock_paths, reader=reader, network_timeout=network_timeout, lint=lint)
    findings = run_rules(ctx, repo_rules)
    for problem in cfg.problems:
        findings.append(Finding(ERROR, "allow.config", allow_mod.ALLOW_FILE, 1, problem))
    by_path = {f.path: f for f in files}
    kept, allowed = apply_allows(findings, cfg, by_path, today)
    kept.sort(key=lambda f: (f.level != ERROR, f.path, f.line, f.rule))
    rows = with_fingerprints(kept, by_path)
    fps, problems = baseline_mod.load(root)
    for problem in problems:
        rows.append(dict(Finding(ERROR, "allow.config", baseline_mod.BASELINE_FILE, 1, problem).__dict__, fp=""))
    baselined = [r for r in rows if r["fp"] in fps and r["level"] == ERROR]
    remaining = [r for r in rows if not (r["fp"] in fps and r["level"] == ERROR)]
    return summarize(remaining, allowed, len(files), time.monotonic() - started, effective_mode, ctx.notes, baselined)


# --- mode ごとの入口 -----------------------------------------------------------------------------

def _tools_present() -> bool:
    return shutil.which("pip-audit") is not None or shutil.which("npm") is not None


def cmd_pre_push(args: argparse.Namespace) -> int:
    root = args.root
    lines = sys.stdin.read().splitlines() if not sys.stdin.isatty() else []
    ranges = pre_push_ranges(root, lines)
    if not ranges:
        print(f"{PREFIX} 見る差分が無い(削除の push か、ref の行が無い)", file=sys.stderr)
        return 0
    worst = 0
    for base, head in ranges:
        if base.startswith("__log__:"):
            paths = sorted(set(p for p in base[len("__log__:"):].split("\0") if p))
        else:
            paths = changed_files(root, base, head)
        reader = CommitReader(root, head)
        try:
            all_paths = ls_files(root, head)
            paths = [p for p in paths if p in set(all_paths)]  # 途中の commit で消えたファイルは見ない
            repo_rules = any(p.endswith(REPO_RULE_TRIGGER) or _looks_like_app(reader, p) for p in paths)
            lock_paths = [p for p in paths if os.path.basename(p) in LOCK_NAMES]
            extended = args.extended if args.extended is not None else bool(lock_paths) and _tools_present()
            summary = check(root, paths, all_paths, mode=args.mode, extended=extended, reader=reader.read,
                            repo_rules=repo_rules, lock_paths=lock_paths, network_timeout=args.network_timeout,
                            lint=args.lint and not _worktree_dirty(root, paths))
        finally:
            reader.close()
        print(f"{PREFIX} {head[:12]}({len(paths)} ファイルの差分)", file=sys.stderr)
        if args.json:
            print(json.dumps(summary, ensure_ascii=False))
        else:
            print_report(summary, out=sys.stderr)
        if summary["blocked"]:
            worst = 1
    if worst:
        print(f"{PREFIX} 直すか、理由を添えて許可(行の `gate-allow: <規則> <理由>` か .security-gate.toml)する。"
              "設計: fleet-skills docs/security-gate-design.md", file=sys.stderr)
    return worst


def _worktree_dirty(root: Path, paths: List[str]) -> bool:
    """pre-push は commit の中身を見るが、linter は作業ツリーのファイルを読む。差分のファイルが作業ツリーで変わっていれば linter を流さない。"""
    if not paths:
        return False
    p = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--", *paths], capture_output=True, text=True)
    return bool(p.stdout.strip())


def _looks_like_app_file(root: Path, rel: str) -> bool:
    if not rel.endswith((".py", ".js", ".ts", ".mjs")):
        return False
    text = read_text(root / rel) or ""
    return "FastAPI(" in text or "Flask(" in text or "express()" in text or "createServer(" in text


def _looks_like_app(reader: CommitReader, rel: str) -> bool:
    if not rel.endswith((".py", ".js", ".ts", ".mjs")):
        return False
    text = reader.read(rel) or ""
    return "FastAPI(" in text or "Flask(" in text or "express()" in text or "createServer(" in text


def cmd_ci(args: argparse.Namespace) -> int:
    root = args.root
    all_paths = ls_files(root)
    if args.base:
        mb = subprocess.run(["git", "-C", str(root), "merge-base", args.base, "HEAD"], capture_output=True, text=True)
        base = mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else args.base
        paths = changed_files(root, base, "HEAD")
        repo_rules = any(p.endswith(REPO_RULE_TRIGGER) or _looks_like_app_file(root, p) for p in paths)
    else:
        paths = all_paths
        repo_rules = True
    extended = True if args.extended is None else args.extended
    summary = check(root, paths, all_paths, mode=args.mode, extended=extended, repo_rules=repo_rules,
                    network_timeout=args.network_timeout, lint=args.lint)
    return _emit(summary, args)


def cmd_scan(args: argparse.Namespace) -> int:
    root = args.root
    try:
        all_paths = ls_files(root)
    except RuntimeError:
        all_paths = [str(p.relative_to(root)).replace(os.sep, "/") for p in root.rglob("*") if p.is_file()]
    if args.paths:
        wanted_prefixes = tuple(os.path.normpath(p) for p in args.paths)
        paths = [p for p in all_paths if p == "." or p.startswith(wanted_prefixes) or any(p.startswith(w + "/") for w in wanted_prefixes)]
    else:
        paths = all_paths
    extended = bool(args.extended)
    summary = check(root, paths, all_paths, mode=args.mode, extended=extended, repo_rules=not args.paths,
                    network_timeout=args.network_timeout, lint=args.lint)
    return _emit(summary, args)


def cmd_baseline(args: argparse.Namespace) -> int:
    """今の全体スキャンの error(baseline に入っているものも含めて)を指紋にして出す。--write で repo に書く。"""
    root = args.root
    all_paths = ls_files(root)
    extended = bool(args.extended)
    summary = check(root, all_paths, all_paths, mode="warn", extended=extended, repo_rules=True,
                    network_timeout=args.network_timeout, lint=args.lint)
    rows = list(summary["findings"]) + list(summary["baselined_findings"])  # type: ignore[arg-type]
    data = baseline_mod.build(rows, _dt.date.today().isoformat())
    text = json.dumps(data, ensure_ascii=False, indent=1) + "\n"
    if args.write:
        (root / baseline_mod.BASELINE_FILE).write_text(text, encoding="utf-8")
        print(f"{PREFIX} {baseline_mod.BASELINE_FILE} に {data['count']} 件を書いた", file=sys.stderr)
    else:
        print(text, end="")
    return 0


def _emit(summary: Dict[str, object], args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=None))
    else:
        print_report(summary)
    if args.summary_file:
        _write_step_summary(Path(args.summary_file), summary)
    return 1 if summary["blocked"] else 0


def _write_step_summary(path: Path, summary: Dict[str, object]) -> None:
    rows = ["## security-gate", "",
            f"mode `{summary['mode']}` / error **{summary['errors']}** / warn {summary['warns']} / "
            f"baseline {summary['baselined']}(既存) / allowed {summary['allowed']} / files {summary['files']} / {summary['seconds']}s", ""]
    if summary["findings"]:
        rows += ["| level | rule | path | message |", "|---|---|---|---|"]
        for f in summary["findings"]:  # type: ignore[union-attr]
            rows.append(f"| {f['level']} | `{f['rule']}` | `{f['path']}:{f['line']}` | {f['message'].replace('|', '/')} |")
    if summary["allowed_findings"]:
        rows += ["", "### 許可(理由付き)", "", "| rule | path | reason |", "|---|---|---|"]
        for f in summary["allowed_findings"]:  # type: ignore[union-attr]
            rows.append(f"| `{f['rule']}` | `{f['path']}:{f['line']}` | {f['reason'].replace('|', '/')} |")
    if summary["notes"]:
        rows += ["", "### 検査できなかったこと", ""] + [f"- {n}" for n in summary["notes"]]  # type: ignore[union-attr]
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(rows) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    S = argparse.SUPPRESS  # 副命令の後ろに書いた option が前のものを上書きしないよう、既定は後で入れる
    common = argparse.ArgumentParser(add_help=False, argument_default=S)
    common.add_argument("--root", type=Path)
    common.add_argument("--mode", choices=("warn", "block"))
    common.add_argument("--json", action="store_true")
    common.add_argument("--extended", dest="extended", action="store_true", help="pip-audit・npm audit も流す")
    common.add_argument("--no-extended", dest="extended", action="store_false")
    common.add_argument("--network-timeout", type=float)
    common.add_argument("--no-lint", dest="lint", action="store_false", help="linter(ruff・shellcheck・eslint・actionlint)を流さない")
    common.add_argument("--summary-file")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, parents=[common])
    ap.add_argument("--rules", action="store_true", help="規則の一覧を出す")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("pre-push", parents=[common])
    p.add_argument("remote", nargs="?")
    p.add_argument("url", nargs="?")
    p = sub.add_parser("ci", parents=[common])
    p.add_argument("--base")
    p = sub.add_parser("scan", parents=[common])
    p.add_argument("paths", nargs="*")
    p = sub.add_parser("baseline", parents=[common], help="全体スキャンの error から .security-gate-baseline.json を作る(--write で書く)")
    p.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)
    defaults = {"root": None, "mode": None, "json": False, "extended": None, "network_timeout": 30.0, "lint": True,
                "summary_file": os.environ.get("GITHUB_STEP_SUMMARY"), "rules": False}
    for key, value in defaults.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    if args.rules:
        for rid, level in sorted(RULE_LEVELS.items()):
            print(f"{level:5} {rid}")
        return 0
    if args.root is None:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        args.root = Path(top.stdout.strip()) if top.returncode == 0 else Path.cwd()
    args.root = args.root.resolve()
    if args.cmd == "pre-push":
        return cmd_pre_push(args)
    if args.cmd == "ci":
        return cmd_ci(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "baseline":
        return cmd_baseline(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        print(f"{PREFIX} 検査できなかった({e})", file=sys.stderr)
        sys.exit(1)
