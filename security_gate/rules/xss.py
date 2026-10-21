"""xss.*: innerHTML などのエスケープ無し、upload の同一 origin 配信。設計 §1 の 7。"""

from __future__ import annotations

import re
from typing import List

from ..model import ERROR, JS_EXT, MARKUP_EXT, PY_EXT, WARN, Context, Finding, SourceFile, is_comment_line

SINK_ASSIGN_RE = re.compile(r"\.(innerHTML|outerHTML)\s*(\+=|=)\s*(?P<rhs>.+?)\s*;?\s*$")
INSERT_RE = re.compile(r"\binsertAdjacentHTML\s*\(\s*[\"'][^\"']+[\"']\s*,\s*(?P<rhs>.+)\)")
DOC_WRITE_RE = re.compile(r"\bdocument\.write(?:ln)?\s*\(\s*(?P<rhs>.+)\)")
LITERAL_RE = re.compile(r"^(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|`[^`$]*`|\"\"|''|``)\s*;?$")
SANITIZE_RE = re.compile(r"DOMPurify|sanitize|escapeHtml|escapeHTML|escape\(|encodeURIComponent|textContent|he\.encode")
DANGEROUS_RE = re.compile(r"dangerouslySetInnerHTML|\bv-html\s*=")
PY_SINKS = [
    (re.compile(r"\brender_template_string\s*\(\s*(f[\"']|[A-Za-z_])"), "render_template_string に動的な文字列。render_template とテンプレートに分ける"),
    (re.compile(r"\bMarkup\s*\(\s*(f[\"']|[A-Za-z_])"), "Markup() に変数。markupsafe.escape を通す"),
    (re.compile(r"\bHTMLResponse\s*\(\s*(content\s*=\s*)?(f[\"']|[A-Za-z_])"), "HTMLResponse に動的な文字列。html.escape を通すかテンプレートにする"),
    (re.compile(r"\bautoescape\s*=\s*False\b"), "autoescape=False"),
]
SAFE_FILTER_RE = re.compile(r"\|\s*safe\b")
UPLOAD_SERVE_RE = re.compile(r"(?i)(send_from_directory\s*\(\s*[^,]*upload|StaticFiles\s*\(\s*directory\s*=\s*[^,)]*upload|"
                             r"express\.static\s*\([^)]*upload|serve_static\s*\([^)]*upload|static_folder\s*=\s*[^,)]*upload)")


def _dynamic(rhs: str) -> bool:
    rhs = rhs.strip()
    if LITERAL_RE.match(rhs) or SANITIZE_RE.search(rhs):
        return False
    return True


def check_markup(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in (JS_EXT | MARKUP_EXT):
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        if DANGEROUS_RE.search(line) and not SANITIZE_RE.search(line):
            out.append(Finding(ERROR, "xss.sink", f.path, i, "dangerouslySetInnerHTML / v-html。sanitize を通すかテキストにする"))
            continue
        for pat, what in ((SINK_ASSIGN_RE, "innerHTML"), (INSERT_RE, "insertAdjacentHTML"), (DOC_WRITE_RE, "document.write")):
            m = pat.search(line)
            if m and _dynamic(m.group("rhs")):
                out.append(Finding(ERROR, "xss.sink", f.path, i, f"{what} に動的な値。textContent か、escape した上で入れる"))
                break
        if f.ext in (".html", ".htm", ".jinja", ".j2", ".tmpl") and SAFE_FILTER_RE.search(line):
            out.append(Finding(WARN, "xss.sink", f.path, i, "|safe。値の出どころを確かめる"))
    return out


def check_py(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in PY_EXT or f.is_test:
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line) or "escape(" in line:
            continue
        for pat, what in PY_SINKS:
            if pat.search(line):
                out.append(Finding(ERROR, "xss.sink", f.path, i, what))
                break
    return out


def check_upload_served(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in (PY_EXT | JS_EXT) or f.is_test:
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line) or "attachment" in line:
            continue
        if UPLOAD_SERVE_RE.search(line):
            out.append(Finding(ERROR, "xss.upload-served", f.path, i,
                               "upload されたものを同じ origin から配信。Content-Disposition: attachment を付けるか別の origin にする"))
    return out
