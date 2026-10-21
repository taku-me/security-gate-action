#!/bin/bash
# 公開の写し taku-me/security-gate-action(main)が、fleet-skills main から作る中身と同じかを見る。設計: docs/security-gate-design.md §2.2
# 公開 repo の caller は写しを呼ぶので、写しが古いと公開 repo だけ古い検査で通ってしまう。違えば exit 1(直し方を出す)。
# 写しがまだ無い時は ::warning を出して exit 0(公開 repo に caller を置く前の段)。
set -euo pipefail
MIRROR="${MIRROR_URL:-https://github.com/taku-me/security-gate-action}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sg-mirror.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
if ! git ls-remote --exit-code -q "$MIRROR" refs/heads/main >/dev/null 2>&1; then
    echo "::warning::公開の写し $MIRROR の main がまだ無い。公開 repo の security-gate はまだ動かない"
    exit 0
fi
bash "$SRC/security_gate/publish_action.sh" --tree "$WORK/want"
git clone -q --depth 1 "$MIRROR" "$WORK/have"
if diff -r -q -x .git -x README.md "$WORK/want" "$WORK/have"; then
    echo "mirror-check: 公開の写しは fleet-skills main($(git -C "$SRC" rev-parse --short HEAD))と同じ"
else
    echo "::error::公開の写し $MIRROR が fleet-skills main と違う。直し方: PUBLISH_REMOTE=$MIRROR PUBLISH_BRANCH=main bash security_gate/publish_action.sh --push(push 権のある所で)"
    exit 1
fi
