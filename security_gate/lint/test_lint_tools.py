"""lint 道具の試験。実行: python3 -m unittest security_gate/lint/test_lint_tools.py -v (repo root から)。要 node。
- compare_eslint_base_head.py の eslint 引数が rules/lint.py の _eslint と同じであること(ずれたら FAIL)
- check_minimatch_resolved.js の版判定(prerelease・不明・欠落は FAIL)
"""
import ast
import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compare_eslint_base_head as cmp  # noqa: E402


def lint_py_flags():
    """rules/lint.py の _eslint 内の `_run([exe, ...])` リストから、"--no-config-lookup" 以降の文字列定数(config path 以外)を順に取る。"""
    tree = ast.parse((HERE.parent / "rules" / "lint.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_eslint")
    for call in ast.walk(fn):
        if isinstance(call, ast.Call) and getattr(call.func, "id", "") == "_run":
            lst = call.args[0]
            out = []
            for e in lst.elts:
                if isinstance(e, ast.Constant) and isinstance(e.value, str):
                    out.append(e.value)
                elif isinstance(e, ast.Call):  # str(LINT_DIR / "eslint.config.mjs") = config path の位置
                    out.append("<config>")
                elif isinstance(e, ast.Starred):
                    break
            return out
    raise AssertionError("_eslint の _run 呼び出しが見つからない")


class EslintArgsSync(unittest.TestCase):
    def test_flags_match_lint_py(self):
        got = lint_py_flags()
        self.assertEqual(got, cmp.ESLINT_FLAGS + ["--"], f"lint.py の _eslint の引数と compare の ESLINT_FLAGS がずれた: {got}")


class MinimatchCheck(unittest.TestCase):
    def run_check(self, payload):
        return subprocess.run(["node", str(HERE / "check_minimatch_resolved.js")], input=payload,
                              capture_output=True, text=True).returncode

    def tree(self, ver):
        d = {"version": ver} if ver is not None else {}
        return json.dumps({"dependencies": {"a": {"version": "1", "dependencies": {"minimatch": d}}}})

    def test_cases(self):
        for ver, rc in [("11.0.1", 0), ("11.0.2", 0), ("10.2.6", 1), ("11.0.1-beta.1", 1), ("11.0.1+build", 1), (None, 1)]:
            self.assertEqual(self.run_check(self.tree(ver)), rc, ver)
        self.assertEqual(self.run_check('{"dependencies":{}}'), 1)
        self.assertEqual(self.run_check("not json"), 1)


if __name__ == "__main__":
    unittest.main()
