"""規則の登録。id・level・説明は docs/security-gate-design.md §1 の表と 1 対 1。"""

from __future__ import annotations

from typing import List

from ..model import ERROR, WARN, Rule
from . import actions, deps, docker, inject, lint, pathsafe, secrets, server, xss

RULES: List[Rule] = [
    Rule("secret.pattern", ERROR, "決まった形の秘密(API キー・トークン・秘密鍵・webhook)", file_rule=secrets.check_patterns),
    Rule("secret.assignment", ERROR, "秘密らしい名前へのリテラルの代入", file_rule=secrets.check_assignment),
    Rule("secret.env-file", ERROR, ".env が追跡されている", file_rule=secrets.check_env_file),
    Rule("secret.fallback-default", ERROR, "秘密の環境変数の固定の既定値", file_rule=secrets.check_fallback_py),
    Rule("secret.fallback-default", ERROR, "(JS)", file_rule=secrets.check_fallback_js),
    Rule("secret.timing-compare", ERROR, "秘密を == で比べる", file_rule=secrets.check_timing_py),
    Rule("secret.timing-compare", ERROR, "(JS)", file_rule=secrets.check_timing_js),
    Rule("bind.all-interfaces", ERROR, "0.0.0.0 で待つ", file_rule=server.check_bind),
    Rule("server.debug", ERROR, "debug・reload を付けて起動", file_rule=server.check_debug),
    Rule("web.cors-any", ERROR, "CORS を全 origin に開く", file_rule=server.check_cors),
    Rule("web.docs-public", WARN, "FastAPI の /docs が公開", file_rule=server.check_docs_public),
    Rule("web.no-origin-check", ERROR, "Origin/Sec-Fetch-Site の確かめが無い(repo 単位)", repo_rule=server.check_web_presence),
    Rule("inject.shell", ERROR, "shell=True・os.system・execSync の連結", file_rule=inject.check_py),
    Rule("inject.shell", ERROR, "(JS)", file_rule=inject.check_js),
    Rule("inject.shell", ERROR, "(sh)", file_rule=inject.check_sh),
    Rule("path.traversal", ERROR, "request 由来の値をそのままパスに", file_rule=pathsafe.check_py),
    Rule("path.traversal", ERROR, "(JS)", file_rule=pathsafe.check_js),
    Rule("xss.sink", ERROR, "innerHTML などにエスケープ無し", file_rule=xss.check_markup),
    Rule("xss.sink", ERROR, "(Python)", file_rule=xss.check_py),
    Rule("xss.upload-served", ERROR, "upload を同一 origin から配信", file_rule=xss.check_upload_served),
    Rule("actions.no-permissions", ERROR, "workflow の permissions・固定・pull_request_target・式の注入・pipefail",
         file_rule=actions.check_workflow),
    Rule("ci.pipe-without-pipefail", WARN, "(sh)", file_rule=actions.check_sh_pipefail),
    Rule("docker.eol-image", ERROR, "EOL の base image・タグ未固定", file_rule=docker.check_images),
    Rule("deps.no-lockfile", ERROR, "lockfile が無い(repo 単位)", repo_rule=docker.check_lockfiles),
    Rule("deps.vulnerable", ERROR, "既知の脆弱性のある依存(拡張)", repo_rule=deps.check_deps, extended=True),
    Rule("lint.*", ERROR, "中央の設定の linter(ruff S/ASYNC・shellcheck・eslint security・actionlint)。道具があれば流す",
         repo_rule=lint.check_lint, lint=True),
]

# 出力に出る規則 id の一覧(level は Finding が持つ。ここは設計書との照合と --rules 用)
RULE_LEVELS = {
    "secret.pattern": ERROR, "secret.assignment": ERROR, "secret.env-file": ERROR, "secret.fallback-default": ERROR,
    "secret.timing-compare": ERROR, "bind.all-interfaces": ERROR, "server.debug": ERROR, "web.no-auth": WARN,
    "web.no-origin-check": ERROR, "web.no-host-check": ERROR, "web.cors-any": ERROR, "web.no-security-headers": WARN,
    "web.docs-public": WARN, "inject.shell": ERROR, "inject.ssh-unquoted": ERROR, "inject.git-arg": ERROR,
    "inject.argv-unbound-value": WARN, "path.traversal": ERROR, "path.proxy-unnormalized": ERROR, "xss.sink": ERROR,
    "xss.upload-served": ERROR, "actions.no-permissions": ERROR,
    "actions.unpinned": ERROR, "actions.pull-request-target": ERROR, "actions.expression-injection": ERROR,
    "ci.pipe-without-pipefail": ERROR, "docker.eol-image": ERROR, "docker.untagged-image": ERROR,
    "deps.no-lockfile": ERROR, "deps.vulnerable": ERROR, "deps.unchecked": WARN, "allow.no-reason": ERROR,
    "allow.expired": WARN, "allow.config": ERROR,
    "lint.ruff.<S/ASYNC の規則>": "error(RUFF_ERROR の表)/warn", "lint.shellcheck.<SC>": "error/warn(severity)",
    "lint.eslint.security.<規則>": "error/warn(設定)", "lint.actionlint.<kind>": ERROR, "lint.unavailable": "note",
}
