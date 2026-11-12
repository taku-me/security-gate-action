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
