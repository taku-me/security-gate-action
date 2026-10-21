"""docker.*・deps.no-lockfile: base image の EOL・タグ未固定、lockfile の有無。設計 §1 の 1 と 11。"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Set, Tuple

from ..model import ERROR, Context, Finding, SourceFile, is_comment_line

# image:tag の prefix → EOL の日(その日を過ぎていれば error)。出どころ: endoflife.date(2026-10-20 に読んだ)
EOL: Dict[str, str] = {
    "node:14": "2023-04-30", "node:16": "2023-09-11", "node:18": "2025-04-30", "node:20": "2026-04-30",
    "python:3.7": "2023-06-27", "python:3.8": "2024-10-07", "python:3.9": "2025-10-31",
    "ubuntu:18.04": "2023-05-31", "ubuntu:20.04": "2025-05-31",
    "debian:buster": "2024-06-30", "debian:10": "2024-06-30", "debian:bullseye": "2026-08-31", "debian:11": "2026-08-31",
    "alpine:3.16": "2024-05-23", "alpine:3.17": "2024-11-22", "alpine:3.18": "2025-05-09", "alpine:3.19": "2025-11-01",
    "ruby:3.0": "2024-04-23", "ruby:3.1": "2025-03-31", "golang:1.21": "2024-08-13", "golang:1.22": "2025-02-11",
    "nginx:1.24": "2024-05-29", "postgres:12": "2024-11-14", "postgres:13": "2025-11-13", "redis:6": "2025-04-30",
    "mysql:5.7": "2023-10-31",
}
FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?", re.I)
IMAGE_RE = re.compile(r"^\s*image:\s*[\"']?(?P<image>[^\s\"'#]+)")
COMPOSE_NAME_RE = re.compile(r"(^|/)(docker-)?compose[^/]*\.ya?ml$")
PY_LOCKS = ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.txt", "requirements.lock", "requirements-lock.txt")
JS_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")


def _split(image: str) -> Tuple[str, Optional[str], bool]:
    """(名前, タグ, digest 付きか)。"""
    digest = "@sha256:" in image
    base = image.split("@", 1)[0]
    if "${" in base or "$" in base:
        return base, "variable", digest
    name, tag = base, None
    last_slash = base.rfind("/")
    colon = base.rfind(":")
    if colon > last_slash:
        name, tag = base[:colon], base[colon + 1:]
    short = name.split("/")[-1] if name.startswith(("docker.io/library/",)) else name
    return short, tag, digest


def _image_problem(image: str, today: str, stages: Set[str]) -> Optional[Tuple[str, str]]:
    if image.lower() == "scratch" or image in stages:
        return None
    name, tag, digest = _split(image)
    if tag == "variable":
        return None
    if digest:
        return None
    if tag is None or tag == "latest":
        return "docker.untagged-image", f"{image}: タグが無いか latest。版(できれば @sha256)で固定する"
    key_full = f"{name}:{tag}"
    for prefix, date in EOL.items():
        pname, ptag = prefix.split(":", 1)
        if name == pname and (tag == ptag or tag.startswith(ptag + ".") or tag.startswith(ptag + "-")) and date <= today:
            return "docker.eol-image", f"{image}: {prefix} は {date} で EOL。新しい版にする"
    del key_full
    return None


def check_images(f: SourceFile, ctx: Context) -> List[Finding]:
    is_dockerfile = f.name in ("Dockerfile", "Containerfile") or f.name.startswith("Dockerfile.") or f.name.endswith(".Dockerfile")
    is_compose = COMPOSE_NAME_RE.search(f.path) is not None
    if not (is_dockerfile or is_compose):
        return []
    out: List[Finding] = []
    stages: Set[str] = set()
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        m = FROM_RE.match(line) if is_dockerfile else IMAGE_RE.match(line)
        if not m:
            continue
        if is_dockerfile and m.group("stage"):
            stages.add(m.group("stage"))
        problem = _image_problem(m.group("image"), ctx.today, stages)
        if problem:
            out.append(Finding(ERROR, problem[0], f.path, i, problem[1]))
    return out


def check_lockfiles(ctx: Context) -> List[Finding]:
    dirs: Dict[str, Set[str]] = {}
    for rel in ctx.all_paths:
        if "node_modules/" in rel or "/.venv/" in rel or rel.startswith(".venv/"):
            continue
        d, name = os.path.split(rel)
        dirs.setdefault(d, set()).add(name)
    out: List[Finding] = []
    for d, names in sorted(dirs.items()):
        label = d or "."
        if "pyproject.toml" in names and not names.intersection(PY_LOCKS):
            text = ctx.read(os.path.join(d, "pyproject.toml") if d else "pyproject.toml") or ""
            if re.search(r"^\s*dependencies\s*=|\[tool\.poetry\]|\[project\]", text, re.M):
                out.append(Finding(ERROR, "deps.no-lockfile", os.path.join(d, "pyproject.toml") if d else "pyproject.toml", 1,
                                   f"{label}: lockfile が無く依存の脆弱性を測れない。uv lock を commit する"))
        if "package.json" in names and not names.intersection(JS_LOCKS):
            text = ctx.read(os.path.join(d, "package.json") if d else "package.json") or ""
            if '"dependencies"' in text or '"devDependencies"' in text:
                out.append(Finding(ERROR, "deps.no-lockfile", os.path.join(d, "package.json") if d else "package.json", 1,
                                   f"{label}: package-lock.json が無く npm audit できない。npm install で作って commit する"))
    return out
