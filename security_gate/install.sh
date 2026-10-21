#!/bin/bash
# ① 各マシンの pre-push の配線。設計: docs/security-gate-design.md §2.1
#
#   bash security_gate/install.sh          # 何をするか出すだけ
#   bash security_gate/install.sh --apply  # 写しを置き、確かめてから core.hooksPath を global に設定する
#
# やること(反証 §9(運用)#1・#13 により「写し → 確かめ → 設定」の順):
#   1. githooks/fleet/ を ~/.local/share/fleet-hooks/ に写す(checkout の枝を変えても・消しても hook が残るため)
#   2. 写しの pre-push を空の stdin で流し、security-gate: の行が出ることを確かめる(出なければ設定せず 1 で止める)
#   3. git config --global core.hooksPath ~/.local/share/fleet-hooks
#   4. ~/projects/*/ のうち local に core.hooksPath がある repo を列挙する(変えない。atoTerminal・task-sync は repo 側の
#      pre-push が gate を呼ぶ。設計 §7)。そこに gate が無ければ警告
# 2 回目以降も同じ(写しを更新する。git pull の後に流し直す)。
set -u
resolve_self() {
    local src="${BASH_SOURCE[0]}" dir
    while [ -L "$src" ]; do
        dir="$(cd "$(dirname "$src")" && pwd -P)"
        src="$(readlink "$src")"
        case "$src" in /*) ;; *) src="$dir/$src" ;; esac
    done
    cd "$(dirname "$src")" && pwd -P
}
HERE="$(resolve_self)"
FLEET_ROOT="$(cd "$HERE/.." && pwd -P)"
SRC_DIR="$FLEET_ROOT/githooks/fleet"
COPY_DIR="${FLEET_HOOKS_COPY:-$HOME/.local/share/fleet-hooks}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1
P="security-gate(install):"

[ -d "$SRC_DIR" ] || { echo "$P $SRC_DIR が無い(fleet-skills の枝が古い)。止める" >&2; exit 1; }

current="$(git config --global --get core.hooksPath 2>/dev/null || true)"
if [ -n "$current" ] && [ "$current" != "$COPY_DIR" ]; then
    echo "$P ⚠ global の core.hooksPath が別の場所を指している: $current。上書きする前に中身を確かめる" >&2
    [ $APPLY -eq 1 ] && exit 1
fi

echo "$P 写す: $SRC_DIR → $COPY_DIR"
if [ $APPLY -eq 1 ]; then
    mkdir -p "$COPY_DIR"
    # symlink は symlink のまま写す(chain.sh への相対リンク)
    (cd "$SRC_DIR" && tar cf - .) | (cd "$COPY_DIR" && tar xf -)
    chmod +x "$COPY_DIR/pre-push" "$COPY_DIR/chain.sh"
    out="$(cd "$FLEET_ROOT" && echo "" | FLEET_SKILLS_DIR="$FLEET_ROOT" bash "$COPY_DIR/pre-push" origin https://example.invalid 2>&1)"
    if ! echo "$out" | grep -q "security-gate"; then
        echo "$P ⚠ 写しの pre-push が security-gate の行を出さない。core.hooksPath は設定しない: $out" >&2
        exit 1
    fi
    echo "$P ✓ 写しの pre-push が流れる: $(echo "$out" | grep security-gate | head -1)"
    if [ "$current" != "$COPY_DIR" ]; then
        git config --global core.hooksPath "$COPY_DIR"
        echo "$P git config --global core.hooksPath $COPY_DIR"
    else
        echo "$P core.hooksPath は既に $COPY_DIR"
    fi
else
    echo "$P git config --global core.hooksPath $COPY_DIR(--apply で書く)"
fi

for d in "$HOME"/projects/*/ /Volumes/*/projects/*/; do
    [ -d "$d/.git" ] || [ -f "$d/.git" ] || continue
    local_path="$(git -C "$d" config --local --get core.hooksPath 2>/dev/null || true)"
    [ -z "$local_path" ] && continue
    case "$local_path" in /*) hp="$local_path" ;; *) hp="$d/$local_path" ;; esac
    if [ -f "$hp/pre-push" ] && grep -q "security-gate\|security_gate" "$hp/pre-push" 2>/dev/null; then
        echo "$P $(basename "$d"): local の core.hooksPath=$local_path(pre-push が gate を呼ぶ: OK)"
    else
        echo "$P ⚠ $(basename "$d"): local の core.hooksPath=$local_path で global が効かず、pre-push が gate を呼んでいない" >&2
    fi
done
echo "$P 確かめ: git config --global --get core.hooksPath / ls $COPY_DIR"
