"""actions.*・ci.*: GitHub Actions の権限・固定・pull_request_target・式の注入、pipefail。設計 §1 の 9〜10。

yaml の読み手は標準ライブラリに無いので、字下げで読む(workflow は 2 段の字下げが普通)。
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ..model import ERROR, SH_EXT, WARN, Context, Finding, SourceFile, is_comment_line

WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*[\"']?(?P<ref>[^\s\"'#]+)")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")
INJECT_RE = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|"
                       r"head_commit|commits|workflow_run|inputs|client_payload)|github\.head_ref|inputs\.|"
                       r"steps\.[\w-]+\.outputs)")
PIPE_RE = re.compile(r"(?<!\|)\|(?!\|)")
PIPEFAIL_RE = re.compile(r"set\s+-[a-zA-Z]*o\s+pipefail|set\s+-[a-zA-Z]*e[a-zA-Z]*o\s*pipefail|pipefail")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _blocks(lines: List[str], key: str) -> List[Tuple[int, int, int]]:
    """`<key>: |` や `<key>: >` のブロックの (開始行 0 始まり, 終了行(含まない), 字下げ) を返す。1 行の `key: value` も含む。"""
    out = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:-\s+)?" + key + r":\s*(.*)$", lines[i])
        if m:
            indent = len(m.group(1)) + (2 if lines[i].lstrip().startswith("-") else 0)
            value = m.group(2).strip()
            if value in ("|", "|-", "|+", ">", ">-", ">+"):
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > indent):
                    j += 1
                out.append((i, j, indent))
                i = j
                continue
            out.append((i, i + 1, indent))
        i += 1
    return out


def _step_has_bash(lines: List[str], start: int, indent: int) -> bool:
    """同じ step の中に shell: bash があるか(run の前後の、同じ字下げの行を見る)。"""
    i = start - 1
    while i >= 0 and (_indent(lines[i]) >= indent or not lines[i].strip()):
        if re.match(r"^\s*(?:-\s+)?shell:\s*bash", lines[i]):
            return True
        if re.match(r"^\s*-\s+", lines[i]):
            break
        i -= 1
    i = start + 1
    while i < len(lines) and (_indent(lines[i]) >= indent or not lines[i].strip()):
        if re.match(r"^\s*-\s+", lines[i]):
            break
        if re.match(r"^\s*shell:\s*bash", lines[i]):
            return True
        i += 1
    return False


def check_workflow(f: SourceFile, ctx: Context) -> List[Finding]:
    if not WORKFLOW_RE.match(f.path):
        return []
    lines = f.lines
    out: List[Finding] = []
    text = f.text
    # permissions: 最上位か job ごと
    top_perm = any(re.match(r"^permissions:", ln) for ln in lines)
    if not top_perm:
        jobs_start = next((i for i, ln in enumerate(lines) if re.match(r"^jobs:", ln)), None)
        if jobs_start is not None:
            job_names = [i for i in range(jobs_start + 1, len(lines)) if re.match(r"^  [\w-]+:\s*$", lines[i])]
            for idx, start in enumerate(job_names):
                end = job_names[idx + 1] if idx + 1 < len(job_names) else len(lines)
                job_lines = lines[start:end]
                if not any(re.match(r"^    permissions:", ln) for ln in job_lines):
                    out.append(Finding(ERROR, "actions.no-permissions", f.path, start + 1,
                                       f"job {lines[start].strip()[:-1]} に permissions が無い(最上位にも無い)。contents: read から始める"))
        else:
            out.append(Finding(ERROR, "actions.no-permissions", f.path, 1, "permissions が無い"))
    # pull_request_target
    for i, ln in enumerate(lines, 1):
        if re.match(r"^\s*(-\s*)?pull_request_target\b", ln) or re.match(r"^on:\s*\[.*pull_request_target", ln) \
                or re.match(r"^on:\s*pull_request_target\s*$", ln):
            out.append(Finding(ERROR, "actions.pull-request-target", f.path, i,
                               "pull_request_target は fork の PR に secrets と書き込み権限を渡す。pull_request にする"))
    # uses の固定
    for i, ln in enumerate(lines, 1):
        m = USES_RE.match(ln)
        if not m:
            continue
        ref = m.group("ref")
        if ref.startswith("./") or ref.startswith("docker://"):
            if ref.startswith("docker://") and "@sha256:" not in ref:
                out.append(Finding(ERROR, "actions.unpinned", f.path, i, f"{ref}: image を @sha256 で固定する"))
            continue
        if ref.startswith("taku-me/fleet-skills/") and ref.endswith(("@main", "@security-gate-action")):
            continue  # 艦隊の正典は枝で呼ぶ(設計 §2.2。security-gate-action は main から自動で作る枝)
        if ref.startswith("taku-me/security-gate-action/") and ref.endswith("@main"):
            continue  # 公開 repo 用の写し(設計 §2.2「公開 repo」。中身は mirror-check が正典と突き合わせる)
        if not SHA_RE.search(ref):
            out.append(Finding(ERROR, "actions.unpinned", f.path, i, f"{ref}: 40 桁の commit SHA で固定する(# vN をコメントに)"))
    # run: の中の式の注入と pipefail
    has_default_bash = re.search(r"^defaults:\s*\n\s+run:\s*\n\s+shell:\s*bash", text, re.M) is not None
    for start, end, indent in _blocks(lines, "run"):
        body = "\n".join(lines[start:end])
        m = INJECT_RE.search(body)
        if m:
            out.append(Finding(ERROR, "actions.expression-injection", f.path, start + 1 + body[:m.start()].count("\n"),
                               f"run の中に {m.group(0)}。env: に入れてから \"$VAR\" で使う"))
        script = body.split(":", 1)[1] if end == start + 1 else "\n".join(lines[start + 1:end])
        code_lines = [ln for ln in script.splitlines() if not is_comment_line(ln)]
        if any(PIPE_RE.search(ln) for ln in code_lines) and not PIPEFAIL_RE.search(script) \
                and not has_default_bash and not _step_has_bash(lines, start, indent):
            out.append(Finding(ERROR, "ci.pipe-without-pipefail", f.path, start + 1,
                               "run に | があるのに pipefail が無い(既定の shell は bash -e だけ)。shell: bash を付けるか set -o pipefail"))
    return out


def check_sh_pipefail(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in SH_EXT:
        return []
    code = [ln for ln in f.lines if not is_comment_line(ln)]
    if any(PIPE_RE.search(ln) for ln in code) and not PIPEFAIL_RE.search(f.text):
        return [Finding(WARN, "ci.pipe-without-pipefail", f.path, 1, "| があるのに set -o pipefail が無い")]
    return []
