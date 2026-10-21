// security-gate の中央の eslint 設定(eslint-plugin-security)。設計: docs/security-gate-design.md §1.2
// gate.py が `eslint --no-config-lookup --config <この file>` で全 repo に同じ規則をかける。plugin はこの dir の node_modules から読む
// (security_gate/lint/package.json。CI は action が npm ci する。手元は install.sh が npm ci する)。
import security from "eslint-plugin-security";

export default [
  {
    files: ["**/*.{js,mjs,cjs,ts,tsx,jsx}"],
    languageOptions: { ecmaVersion: 2022, sourceType: "module" },
    plugins: { security },
    rules: {
      "security/detect-child-process": "error",
      "security/detect-eval-with-expression": "error",
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-non-literal-regexp": "warn",
      "security/detect-non-literal-require": "error",
      "security/detect-unsafe-regex": "warn",
      "security/detect-possible-timing-attacks": "error",
      "security/detect-pseudoRandomBytes": "error",
      "security/detect-new-buffer": "error",
      "security/detect-no-csrf-before-method-override": "error",
      "security/detect-disable-mustache-escape": "error",
      "security/detect-object-injection": "off",
      "security/detect-bidi-characters": "error",
    },
  },
];
