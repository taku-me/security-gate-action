# security_gate/lint の overrides

`package.json` に `overrides` は無い。`eslint` 10.15.0 以上は `minimatch` を `^11.0.5` で、`@eslint/config-array` 0.23.6 以上も `^11.0.5` で宣言しており、依存の解決だけで minimatch 11 系になる(`npm view eslint@10.15.0 dependencies.minimatch`、`npm view @eslint/config-array@0.23.6 dependencies.minimatch`)。

## minimatch

脆弱性 CVE-2026-118764 / GHSA-g3hv-75wg-m249(脆弱範囲 `>= 7.0.0, < 11.0.1`)を避けるため、解決された全 `minimatch` が 11.0.1 以上であることを、`package.json` や `npm ls` の表示ではなく実際に解決された版で測る(`overrides` が無くても、依存の範囲が古ければ脆弱な版を引く):

```bash
set -o pipefail       # npm ls 自体が失敗した時も止める(pipe の左の失敗を握り潰さない)
cd security_gate/lint
npm ci
npm ls minimatch --all --json | node check_minimatch_resolved.js   # 既定の下限は 11.0.1
echo "rc=$?"          # 0 であること。解決された全 minimatch が厳密な x.y.z で 11.0.1 以上
npm audit             # 0 件であること
```

`eslint` を上げる・下げる時、または `overrides` を足す時も、上の測定と下の `compare_eslint_base_head.py` を流す。`overrides` で押し上げるのは、依存の ESLint 系が minimatch 11 以上を許さない版に戻す時だけにする。

## eslint の base/head 比較(再利用できる道具)

lockfile や overrides を変えた時に、eslint の結果が変わっていないことを測る。`compare_eslint_base_head.py` が、2 つの git ref の `security_gate/lint/`(`package.json`・`package-lock.json`・`eslint.config.mjs`)をそれぞれ一時 dir に取り出して `npm ci` し、gate.py(`rules/lint.py` の `_eslint`)と同じ引数で eslint を 4 通り(ディレクトリ指定・絶対パスのファイル列挙・glob・`--ignore-pattern`)流して、ルール別の件数・対象/無視されたファイル・全メッセージを比べる。

```bash
python3 security_gate/lint/compare_eslint_base_head.py --base-ref <変更前の ref> --head-ref <変更後の ref> [--fixture <dir>]
```

- 検査用ファイル(js/mjs/cjs/ts/tsx/jsx・深い階層・`.hidden/`・`dist/`・`node_modules` 内・`.txt`・clean・bidi 文字)は、`--fixture` を省くと実行時に repo の外の一時 dir へ作り、終われば消える
- exit 0: 4 通りとも一致 / 1: 差がある(差の中身を出す) / 2: 検査できなかった(`npm ci` 失敗・eslint 出力なし・何も lint されなかった mode がある。「差なし」とは別)
- 要 node 18 以上・npm・git・network

## 実行のしかた(手動と CI)

どちらも今は**手動**で流す。この repo の CI(GitHub Actions)にはこれらを流す job は無い(lockfile や overrides を変えた PR の作者が手で流し、結果を PR 本文に貼る)。

```bash
# 版の判定と eslint 引数の同期の試験(要 node。repo root から)
python3 -m unittest security_gate/lint/test_lint_tools.py -v
# overrides を変えた時: 上の「解決された版の測定」と、下の base/head 比較
```

`test_lint_tools.py` は、`compare_eslint_base_head.py` の eslint 引数が `rules/lint.py` の `_eslint` と同じであること(ずれたら FAIL)と、`check_minimatch_resolved.js` の判定(prerelease・版不明・欠落は FAIL)を確かめる。

## 配布先の制約

この lint 設定を他の repo へ配る場合、eslint の engines(`^20.19.0 || ^22.13.0 || >=24`)を満たさない Node では動かせない(`npm view eslint@10.15.0 engines`。minimatch 11 の engines は `npm view minimatch@11.0.1 engines`)。

動作は Node の engines 要件(`npm view minimatch@<版> engines`)に依存する。action の実行環境の Node は `security-gate/action.yml` の `node-version` で決まる。
