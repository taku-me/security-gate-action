# security_gate/lint の overrides

`package.json` の `overrides` は、依存の ESLint 系が宣言する範囲の外へ版を押し上げている。

## minimatch

脆弱性のある版を避けるため、`minimatch` を 11 系に固定している(`overrides.minimatch`)。

外す条件: `eslint` と `@eslint/config-array` が minimatch 11 以上を許す版を出した時。

外した後に確かめること(値ではなく測り方):

```bash
cd security_gate/lint
npm ls minimatch --all   # 「overridden」が出ず、脆弱な版が無いこと
npm audit                # 0 件であること
```

動作は Node の engines 要件(`npm view minimatch@<版> engines`)に依存する。action の実行環境の Node は `security-gate/action.yml` の `node-version` で決まる。

## minimatch 11 への上書きの検証記録(この記録は履歴。現在値は上の確かめ方で測る)

- 対象: CVE-2026-118764 / GHSA-g3hv-75wg-m249(脆弱範囲 `>= 7.0.0, < 11.0.1`、修正版 11.0.1)
- 固定の理由: `11.0.1` は修正版そのもの。範囲(`^11`)にすると将来の 11 系の版を黙って引くので、修正版に固定し、外す条件が揃った時に overrides ごと消す。`package.json` を更新したら `npm ci` が通ることを確かめる
- Node: minimatch 11.0.1 の engines は `18 || 20 || >=22`(`npm view minimatch@11.0.1 engines`)。この action の lint は `security-gate/action.yml` の `actions/setup-node` が `node-version: "22"` を指定した後に `npm ci` を実行するので要件を満たす
- 新しい推移依存 `@isaacs/nonrecursive-glob-match`: minimatch 11.0.1 自身の依存。maintainer は isaacs(minimatch と同じ)、ライセンス BlueOak-1.0.0(`npm view @isaacs/nonrecursive-glob-match license maintainers`)。lockfile に integrity が固定されている
- eslint の base(origin/main の lockfile)と head の比較: 意図的にルール違反を含む 11 ファイル(`.js` `.mjs` `.cjs` `.ts` `.tsx` `.jsx`・深い階層・`.hidden/`・`dist/`・`x.y/z/`・`node_modules` 内・`.txt`・clean・bidi 文字)で、gate.py と同じ引数により 4 通り(ディレクトリ指定・ファイル列挙・glob・`--ignore-pattern`)。ルール別の件数・対象になったファイル・無視されたファイル・全メッセージ(ルール・行・桁・本文)が 4 通りとも base と head で完全に一致した
- `npm audit` と `npm audit --omit=dev`: head で 0 件、GHSA-g3hv-75wg-m249 は無い。`npm ls minimatch --all` は 11.0.1 だけ(base は 3 件の moderate で minimatch 10.2.6)
