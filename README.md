# security-gate action(自動で作る枝。手で編集しない)

fleet-skills main の `74da5908cde3005028089379e4f7008365684f1f` から `security_gate/publish_action.sh` が作った。中身は `security-gate/`(composite action)と
`security_gate/`(検査の本体・中央の linter の設定)。試験は入れない。正典と設計は main の `docs/security-gate-design.md`。
非公開の repo の caller は `uses: taku-me/fleet-skills/security-gate@security-gate-action`、
公開の repo の caller は `uses: taku-me/security-gate-action/security-gate@main`(この写し)。
