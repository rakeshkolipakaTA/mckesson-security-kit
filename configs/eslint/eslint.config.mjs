// Warden standard ESLint security config (flat config). Used by the scanner, independent of the project's own ESLint setup.
import js from "@eslint/js";
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import tseslint from "typescript-eslint";
import globals from "globals";

const sec = {
  plugins: { security, "no-unsanitized": noUnsanitized },
  rules: {
    ...security.configs.recommended.rules,
    "no-unsanitized/method": "error",
    "no-unsanitized/property": "error",
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
  },
  languageOptions: { globals: { ...globals.node, ...globals.browser }, ecmaVersion: "latest", sourceType: "module",
                     parserOptions: { ecmaFeatures: { jsx: true } } },
  linterOptions: { reportUnusedDisableDirectives: "off" },
};

export default [
  { ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/coverage/**", "**/.security/**", "**/*.min.js", "**/.next/**"] },
  { files: ["**/*.{js,jsx,mjs,cjs}"], ...sec },
  { files: ["**/*.{ts,tsx}"], ...sec, languageOptions: { ...sec.languageOptions, parser: tseslint.parser } },
];
