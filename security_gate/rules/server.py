"""bind.*・server.*・web.*: 待ち受け・debug・CORS・presence の検査。設計 §1 の 3〜4。"""

from __future__ import annotations

import re
from typing import List

from ..model import (CONFIG_EXT, ERROR, JS_EXT, PY_EXT, SH_EXT, WARN, Context, Finding, SourceFile,
                     is_comment_line, wanted)

BIND_EXT = PY_EXT | JS_EXT | SH_EXT | CONFIG_EXT | {".rb", ".go", ".rs", ".php"}
ALL_IFACES_RE = re.compile(r"(?<![\w.])0\.0\.0\.0(?![\w.])|[\"']::[\"']|[\"']\[::\][\"']|(?<![\w:])0:0:0:0:0:0:0:0(?![\w:])")
BIND_CONTEXT_RE = re.compile(r"(?i)host|bind|listen|address|addr|server|serve|run\(|ports?|0\.0\.0\.0:\d|--host|url|http")
NOT_BIND_RE = re.compile(r"(?i)\bin\s*[\[(]|==|!=|\bnot\b|never|avoid|禁止|しない|代わり|instead|warn|error|raise|print\(|log")
COMPOSE_NAME_RE = re.compile(r"(^|/)(docker-)?compose[^/]*\.ya?ml$")
COMPOSE_PORT_RE = re.compile(r"^\s*-\s*[\"']?(?P<host>\d{2,5}):(?P<cont>\d{2,5})(?:/(tcp|udp))?[\"']?\s*(#.*)?$")
PY_EMPTY_HOST_RE = re.compile(r"\(\s*(\"\"|'')\s*,\s*[A-Za-z_0-9.]+\s*\)")
PY_SERVER_WORDS = ("HTTPServer", "TCPServer", "ThreadingHTTPServer", ".bind(", "make_server", "serve(")
JS_LISTEN_RE = re.compile(r"\.listen\s*\((?P<args>[^()]*(?:\([^()]*\)[^()]*)*)\)")
DEBUG_RE = re.compile(r"\b(debug|reload|share|use_reloader)\s*=\s*True\b")
DEBUG_FLAG_RE = re.compile(r"(?<![\w-])--(reload|debug)(?![\w-])")
FLASK_DEBUG_RE = re.compile(r"\bFLASK_DEBUG\s*[=:]\s*[\"']?(1|true|True)\b")
SERVER_WORDS_PY = ("uvicorn", "flask", "Flask", "gradio", "hypercorn", "app.run", "streamlit", "bottle", "aiohttp")
CORS_PATTERNS = [
    re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]"),
    re.compile(r"allow_origin_regex\s*=\s*[\"']\.\*[\"']"),
    re.compile(r"(?i)access-control-allow-origin[\"']?\s*[:,=]\s*[\"']?\*"),
    re.compile(r"\bCORS\(\s*app\s*\)"),
    re.compile(r"\bcors\(\s*\)"),
    re.compile(r"\borigin\s*:\s*(?:[\"']\*[\"']|true(?![\w]))"),
    re.compile(r"(?i)add_header\s+access-control-allow-origin\s+\*"),
]
APP_RE = re.compile(r"\b(FastAPI|Flask|Starlette|Quart|Sanic|Bottle)\s*\(|\bexpress\s*\(\s*\)|http\.createServer\s*\(|"
                    r"\bweb\.Application\s*\(|\bfastify\s*\(|new\s+Hono\s*\(|\bgr\.(Blocks|Interface)\s*\(")
FASTAPI_CALL_RE = re.compile(r"\bFastAPI\s*\((?P<args>[^()]*(?:\([^()]*\)[^()]*)*)\)")
ORIGIN_CHECK_RE = re.compile(r"(?i)sec-fetch-site|headers\.get\(\s*[\"']origin[\"']|headers\[[\"']origin[\"']\]|"
                             r"req\.get\(\s*[\"']origin[\"']|request\.origin|csrf|CSRFProtect|same-origin|sameorigin")
HOST_CHECK_RE = re.compile(r"(?i)allowed_hosts|TrustedHostMiddleware|headers\.get\(\s*[\"']host[\"']|headers\[[\"']host[\"']\]|"
                           r"req\.hostname|req\.headers\.host|SERVER_NAME|host_whitelist|dns.?rebind")
AUTH_RE = re.compile(r"(?i)authorization|bearer|login|session|api[_-]?key|passw|basic_auth|HTTPBasic|oauth|jwt|cookie")
HEADERS_RE = re.compile(r"(?i)x-content-type-options|content-security-policy|x-frame-options|helmet\(|secure_headers|"
                        r"SecurityHeaders|referrer-policy")


def check_bind(f: SourceFile, ctx: Context) -> List[Finding]:
    if (f.ext not in BIND_EXT and not f.name.startswith("Dockerfile")) or f.is_test:
        return []
    out: List[Finding] = []
    compose = COMPOSE_NAME_RE.search(f.path) is not None
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        if ALL_IFACES_RE.search(line) and BIND_CONTEXT_RE.search(line) and not NOT_BIND_RE.search(line):
            out.append(Finding(ERROR, "bind.all-interfaces", f.path, i,
                               "0.0.0.0 で待つ。127.0.0.1(tailnet なら tailscale の IP)に絞る"))
            continue
        if compose:
            m = COMPOSE_PORT_RE.match(line)
            if m:
                out.append(Finding(ERROR, "bind.all-interfaces", f.path, i,
                                   f"compose の ports {m.group('host')}:{m.group('cont')} は全アドレスで開く。"
                                   f"127.0.0.1:{m.group('host')}:{m.group('cont')} にする"))
                continue
        if f.ext in PY_EXT and PY_EMPTY_HOST_RE.search(line) and any(w in line for w in PY_SERVER_WORDS):
            out.append(Finding(ERROR, "bind.all-interfaces", f.path, i, '("", port) は全アドレスで待つ。("127.0.0.1", port) にする'))
            continue
        if f.ext in JS_EXT:
            m = JS_LISTEN_RE.search(line)
            if m and ("app" in line or "server" in line or "http" in line):
                args = m.group("args")
                head = re.split(r"=>|function\b", args, maxsplit=1)[0]
                if head.strip() and not re.search(r"[\"'`]", head) and "host" not in head.lower():
                    out.append(Finding(ERROR, "bind.all-interfaces", f.path, i,
                                       ".listen(port) は全アドレスで待つ。.listen(port, \"127.0.0.1\") にする"))
    return out


def check_debug(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in (PY_EXT | SH_EXT | CONFIG_EXT) and not f.name.startswith("Dockerfile"):
        return []
    out: List[Finding] = []
    py_server = f.ext in PY_EXT and any(w in f.text for w in SERVER_WORDS_PY)
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        if py_server and DEBUG_RE.search(line) and "add_argument" not in line and "def " not in line:
            out.append(Finding(ERROR, "server.debug", f.path, i, f"{DEBUG_RE.search(line).group(1)}=True。本番では外す"))
            continue
        if f.ext in (SH_EXT | CONFIG_EXT) and DEBUG_FLAG_RE.search(line) and not re.search(
                r"add_argument|help=|argparse|usage|\bif\b.*--debug|\$\{?[A-Z_]*DEBUG", line):
            out.append(Finding(ERROR, "server.debug", f.path, i, f"{DEBUG_FLAG_RE.search(line).group(0)} を起動に付けている"))
            continue
        if FLASK_DEBUG_RE.search(line):
            out.append(Finding(ERROR, "server.debug", f.path, i, "FLASK_DEBUG=1"))
    return out


def check_cors(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in (PY_EXT | JS_EXT | CONFIG_EXT | {".conf"}):
        return []
    out: List[Finding] = []
    for i, line in enumerate(f.lines, 1):
        if is_comment_line(line):
            continue
        if any(p.search(line) for p in CORS_PATTERNS):
            out.append(Finding(ERROR, "web.cors-any", f.path, i, "CORS を全 origin に開いている。origin を列挙する"))
    return out


def check_docs_public(f: SourceFile, ctx: Context) -> List[Finding]:
    if f.ext not in PY_EXT or f.is_test:
        return []
    out: List[Finding] = []
    for m in FASTAPI_CALL_RE.finditer(f.text):
        if "docs_url" not in m.group("args"):
            out.append(Finding(WARN, "web.docs-public", f.path, f.text.count("\n", 0, m.start()) + 1,
                               "FastAPI の /docs・/openapi.json が公開。docs_url=None, redoc_url=None, openapi_url=None にする"))
    return out


# --- repo 単位の presence 検査 ---------------------------------------------------------------------

def _app_files(ctx: Context) -> List[str]:
    out = []
    for rel in ctx.all_paths:
        ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
        if ext not in ("py", "js", "mjs", "cjs", "ts") or not wanted(rel):
            continue
        text = ctx.read(rel)
        if text and APP_RE.search(text) and "import" in text:
            out.append(rel)
    return out


def check_web_presence(ctx: Context) -> List[Finding]:
    """app を作る repo に、Origin・Host の確かめ、認証、守りのヘッダの語があるか。無ければ repo に 1 件。"""
    apps = _app_files(ctx)
    if not apps:
        return []
    corpus_parts = []
    for rel in ctx.all_paths:
        ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
        if rel.startswith(".security-gate"):
            continue  # gate 自身の設定・baseline の文言(Sec-Fetch-Site など)で presence を満たさない
        if ext in ("py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "conf", "yml", "yaml", "toml", "json") and wanted(rel):
            text = ctx.read(rel)
            if text:
                corpus_parts.append(text)
    corpus = "\n".join(corpus_parts)
    anchor = sorted(apps)[0]
    out: List[Finding] = []
    if not ORIGIN_CHECK_RE.search(corpus):
        out.append(Finding(ERROR, "web.no-origin-check", anchor, 1,
                           "HTTP の app があるのに Origin / Sec-Fetch-Site の確かめが無い(CSRF)。"
                           "状態を変える経路で Sec-Fetch-Site を見る"))
    if not HOST_CHECK_RE.search(corpus):
        out.append(Finding(ERROR, "web.no-host-check", anchor, 1,
                           "HTTP の app があるのに Host の確かめが無い(DNS rebinding)。許す Host を列挙する"))
    if not AUTH_RE.search(corpus):
        out.append(Finding(WARN, "web.no-auth", anchor, 1, "HTTP の app があるのに認証の語が無い"))
    if not HEADERS_RE.search(corpus):
        out.append(Finding(WARN, "web.no-security-headers", anchor, 1,
                           "守りのヘッダ(X-Content-Type-Options・CSP・X-Frame-Options)が無い"))
    return out
