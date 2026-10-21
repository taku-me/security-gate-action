#!/bin/bash
# composite action を置く枝 `security-gate-action` を main から作り直す。設計: docs/security-gate-design.md §2.2
#
# なぜ要るか(2026-10-20 実測): GitHub は action を取る時に repo を丸ごと展開する。fleet-skills の skills/log/scripts/ には
# repo の外(../../../../task-sync/…)を指す symlink が 3 本あり(各マシンの ~/.claude/skills が使う。消せない)、
# 展開が「Could not find file …/task_db.py」で止まり、他 repo の caller が全部落ちた(task-sync #435 job 118765088615)。
# だから action に要る物(security-gate/・security_gate/、試験と node_modules は除く)だけを置いた枝を、
# main への push のたびに .github/workflows/publish-action.yml がこの script で作り直す。caller は @security-gate-action を指す。
#
#   bash security_gate/publish_action.sh            # 何を置くか出す(push しない)
#   bash security_gate/publish_action.sh --push     # 枝に commit して push する(force は使わない。既存の枝の上に積む)
#   bash security_gate/publish_action.sh --tree DIR # 置く中身だけを DIR に作る(公開の写しとの突き合わせ用。git は触らない)
#
# 公開 repo 用の写し(taku-me/security-gate-action の main)にも同じ中身を置く。公開 repo は非公開の fleet-skills の action を呼べないため。
#   PUBLISH_REMOTE=https://github.com/taku-me/security-gate-action PUBLISH_BRANCH=main bash security_gate/publish_action.sh --push
# 写しに自動で push する鍵は置かない(secret への書き込みは指揮役の権限の判定が止めた。2026-10-21)。
# ずれは .github/workflows/mirror-check.yml が毎日と main への push で見て、違えば落ちる。落ちたら上の 1 行で写しを直す。
set -euo pipefail
BRANCH="${PUBLISH_BRANCH:-security-gate-action}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
build_tree() {  # $1 に action に要る物だけを置く
    local out="$1" d
    for d in security-gate security_gate; do
        mkdir -p "$out/$d"
        (cd "$SRC/$d" && git -C "$SRC" ls-files -z -- "$d" | sed -z "s|^$d/||" | tar cf - --null -T - ) | (cd "$out/$d" && tar xf -)
    done
    rm -rf "$out/security_gate/tests" "$out/security_gate/lint/node_modules"
    find "$out" -name __pycache__ -type d -prune -exec rm -rf {} +
}
if [ "${1:-}" = "--tree" ]; then
    [ -n "${2:-}" ] || { echo "usage: $0 --tree DIR" >&2; exit 2; }
    mkdir -p "$2"; build_tree "$2"; exit 0
fi
REMOTE="${PUBLISH_REMOTE:-$(git -C "$SRC" remote get-url origin)}"
SHA="$(git -C "$SRC" rev-parse HEAD)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sg-action.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
P="security-gate(publish-action):"

if [ -z "${PUBLISH_REMOTE:-}" ] && git -C "$SRC" fetch -q origin "$BRANCH" 2>/dev/null; then
    # fleet-skills 自身の枝。CI では非公開 repo の clone に認証が無いので worktree に落ちる(前からの形)
    git clone -q --branch "$BRANCH" --single-branch "$REMOTE" "$WORK/repo" 2>/dev/null \
        || git -C "$SRC" worktree add -q --detach "$WORK/repo" "origin/$BRANCH"
    echo "$P 既存の枝 $BRANCH の上に積む"
elif [ -n "${PUBLISH_REMOTE:-}" ] && git ls-remote --exit-code -q "$REMOTE" "refs/heads/$BRANCH" >/dev/null 2>&1; then
    git clone -q --branch "$BRANCH" --single-branch "$REMOTE" "$WORK/repo"
    echo "$P 既存の枝 $BRANCH の上に積む"
else
    git init -q -b "$BRANCH" "$WORK/repo"
    git -C "$WORK/repo" remote add origin "$REMOTE"
    echo "$P 枝 $BRANCH を新しく作る"
fi
cd "$WORK/repo"
find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
build_tree "$PWD"
cat > README.md <<README
# security-gate action(自動で作る枝。手で編集しない)

fleet-skills main の \`$SHA\` から \`security_gate/publish_action.sh\` が作った。中身は \`security-gate/\`(composite action)と
\`security_gate/\`(検査の本体・中央の linter の設定)。試験は入れない。正典と設計は main の \`docs/security-gate-design.md\`。
非公開の repo の caller は \`uses: taku-me/fleet-skills/security-gate@security-gate-action\`、
公開の repo の caller は \`uses: taku-me/security-gate-action/security-gate@main\`(この写し)。
README
if [ -n "$(git status --porcelain)" ]; then
    git add -A
    git -c user.name="fleet-skills publish-action" -c user.email="noreply@anthropic.com" commit -q -m "publish security-gate action from main $SHA"
    echo "$P commit: $(git rev-parse --short HEAD)($(git ls-files | wc -l | tr -d ' ') files)"
else
    echo "$P 変更なし(main $SHA と同じ中身)"
fi
if [ "${1:-}" = "--push" ]; then
    git push -q origin "HEAD:refs/heads/$BRANCH"
    echo "$P push した: origin/$BRANCH"
else
    git ls-files | head -40
    echo "$P --push で枝に push する"
fi
