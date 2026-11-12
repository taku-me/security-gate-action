#!/usr/bin/env python3
"""eslint の base/head 比較。lockfile(依存の版)だけが違う 2 つの checkout で、gate.py と同じ引数の eslint を
4 通りの渡し方(directory / 絶対パスのファイル列挙 / glob / --ignore-pattern)で流し、結果の差を出す。

比較するもの: ルール別の件数・対象になったファイル・無視されたファイル・全メッセージ(ルール・行・桁・重さ・本文)。
差が 1 つでもあれば exit 1。検査できなかった(npm ci 失敗・eslint 出力なし)時は exit 2(「差なし」と混ぜない)。

使い方:
  python3 security_gate/lint/compare_eslint_base_head.py --base-ref <ref> --head-ref <ref> [--repo <repo root>] [--fixture <dir>]
  --repo   既定は この script のある repo。--base-ref / --head-ref はその repo の git ref(security_gate/lint の 4 ファイルを取り出す)
  --fixture 省略時は実行時に一時 dir へ「意図的にルール違反を含む」ファイル群を作る(repo の外。終われば消す)
  要 node(>=18)・npm・git・network(npm ci)。base / head ごとに別の一時 dir で `npm ci` する。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
LINT_FILES = ["package.json", "package-lock.json", "eslint.config.mjs"]
BAD = "const cp = require('child_process');\ncp.exec(x);\neval(y);\nconst r = new RegExp(z);\nif (token == secret) {}\n"
FIXTURE_FILES = {
    "a.js": BAD, "b.mjs": BAD, "c.cjs": BAD, "d.ts": BAD, "e.tsx": BAD, "f.jsx": BAD,
    "deep/er/est/g.js": BAD, ".hidden/h.js": BAD, "dist/i.js": BAD, "x.y/z/j.js": BAD,
    "node_modules/pkg/k.js": BAD, "notes.txt": "eval(y)\n", "clean.js": "export const ok = 1;\n",
    "bidi.js": "const s = 'abc‮def';\n",
}


def make_fixture(root: Path) -> None:
    for rel, body in FIXTURE_FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def checkout(repo: Path, ref: str, dest: Path) -> Path:
    d = dest / "lint"
    d.mkdir(parents=True)
    for f in LINT_FILES:
        out = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:security_gate/lint/{f}"],
                             capture_output=True, check=True).stdout
        (d / f).write_bytes(out)
    subprocess.run(["npm", "ci", "--no-audit", "--no-fund", "--loglevel=error"], cwd=d, check=True)
    return d


def modes(fx: Path) -> Dict[str, List[str]]:
    files = sorted(str(p) for p in fx.rglob("*") if p.is_file())
    exts = ["js", "mjs", "cjs", "ts", "tsx", "jsx"]
    return {
        "directory": [str(fx)],
        "file-list": files,
        "globs": [f"{fx}/**/*.{e}" for e in exts],
        "ignore-pattern": ["--ignore-pattern", "**/dist/**", "--", str(fx)],
    }


def run_eslint(lint: Path, fx: Path, args: List[str]) -> Tuple[int, list]:
    # gate.py(rules/lint.py _eslint)と同じ引数。ignore-pattern だけ、その option を足す
    pre, tail = ([], args) if "--" not in args else (args[:args.index("--")], args[args.index("--") + 1:])
    argv = [str(lint / "node_modules/.bin/eslint"), "--no-config-lookup", "--config", str(lint / "eslint.config.mjs"),
            "--format", "json", "--no-error-on-unmatched-pattern", *pre, "--", *tail]
    p = subprocess.run(argv, cwd=fx, capture_output=True, text=True)
    if not p.stdout.strip() or p.returncode not in (0, 1):
        raise RuntimeError(f"eslint 出力なし rc={p.returncode}: {p.stderr.strip()[:300]}")
    return p.returncode, json.loads(p.stdout)


def summarize(rows: list, fx: Path) -> dict:
    counts: Dict[str, int] = {}
    linted, ignored, msgs = [], [], []
    for r in rows:
        rel = os.path.relpath(r["filePath"], str(fx))
        ms = r.get("messages", [])
        if any("File ignored" in (m.get("message") or "") for m in ms):
            ignored.append(rel)
            continue
        linted.append(rel)
        for m in ms:
            rule = m.get("ruleId") or "parse"
            counts[rule] = counts.get(rule, 0) + 1
            msgs.append([rel, rule, m.get("line"), m.get("column"), m.get("severity"), m.get("message")])
    return {"counts": dict(sorted(counts.items())), "linted": sorted(linted), "ignored": sorted(ignored),
            "messages": sorted(msgs, key=lambda x: [str(v) for v in x])}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-ref", required=True)
    ap.add_argument("--head-ref", required=True)
    ap.add_argument("--repo", default=str(HERE.parent.parent))
    ap.add_argument("--fixture")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="eslint-cmp-") as tmp:
        t = Path(tmp).resolve()  # macOS の /var → /private/var。symlink のままだと eslint が「base path の外」で全件を無視する
        fx = Path(a.fixture).resolve() if a.fixture else t / "fixture"
        if not a.fixture:
            make_fixture(fx)
        try:
            lints = {"base": checkout(Path(a.repo), a.base_ref, t / "base"),
                     "head": checkout(Path(a.repo), a.head_ref, t / "head")}
            res = {side: {m: summarize(run_eslint(lint, fx, args)[1], fx) for m, args in modes(fx).items()}
                   for side, lint in lints.items()}
        except (RuntimeError, subprocess.CalledProcessError) as e:
            print(f"検査できなかった(差なしではない): {e}", file=sys.stderr)
            return 2
        empty = [m for m, h in res["head"].items() if not h["messages"]]
        if empty or any(not v["linted"] for side in res.values() for v in side.values()):
            print(f"検査できなかった(差なしではない): 何も lint されなかった mode がある {empty}", file=sys.stderr)
            return 2
        ver = {s: subprocess.run(["node", "-p", "require('minimatch/package.json').version"], cwd=l,
                                 capture_output=True, text=True).stdout.strip() for s, l in lints.items()}
        print(f"fixture files={len(FIXTURE_FILES) if not a.fixture else sum(1 for _ in fx.rglob('*') if _.is_file())}"
              f" base={a.base_ref}(minimatch {ver['base']}) head={a.head_ref}(minimatch {ver['head']})")
        bad = 0
        for m in res["base"]:
            b, h = res["base"][m], res["head"][m]
            same = b == h
            bad += not same
            print(f"[{m}] linted={len(h['linted'])} ignored={len(h['ignored'])} messages={len(h['messages'])} "
                  f"{'IDENTICAL' if same else 'DIFFERENT'}")
            print("  counts(head):", json.dumps(h["counts"], ensure_ascii=False))
            if not same:
                for k in b:
                    if b[k] != h[k]:
                        print(f"  diff {k}:\n    base={json.dumps(b[k], ensure_ascii=False)}\n    head={json.dumps(h[k], ensure_ascii=False)}")
        print("RESULT:", "all modes identical" if not bad else f"{bad} mode(s) differ")
        return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
