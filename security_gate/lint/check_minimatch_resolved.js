// stdin: `npm ls minimatch --all --json` の出力。解決された minimatch が全て MIN 以上なら exit 0。
// 厳密な x.y.z 以外(prerelease・不明・空)は FAIL。1 つでも FAIL なら exit 1。
const MIN = process.argv[2] || "11.0.1";
const strict = /^\d+\.\d+\.\d+$/;
const lt = (a, b) => {
  a = a.split(".").map(Number); b = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
};
let t;
try { t = JSON.parse(require("fs").readFileSync(0, "utf8")); }
catch (e) { console.error("FAIL: npm ls の出力を読めない"); process.exit(1); }
const v = new Set();
(function w(d) {
  for (const [k, x] of Object.entries(d.dependencies || {})) {
    if (k === "minimatch") v.add(x.version === undefined ? "(no version)" : String(x.version));
    w(x);
  }
})(t);
console.log("resolved minimatch:", [...v].join(", ") || "(none)");
const bad = [...v].filter((x) => !strict.test(x) || lt(x, MIN));
if (!v.size || bad.length) {
  console.error(`FAIL: minimatch が ${MIN} 未満・prerelease・版不明・または見つからない: ${bad.join(", ") || "(none)"}`);
  process.exit(1);
}
