import js from "@eslint/js";
import ts from "typescript-eslint";
import hooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default ts.config(
  { ignores: ["node_modules/**", "dist/**", ".wrangler/**", "graphify-out/**"] },
  { files: ["**/*.mjs"], ...js.configs.recommended, languageOptions: { globals: globals.node } },
  { files: ["src/**/*.ts", "src/**/*.tsx", "vite.config.ts"], extends: [js.configs.recommended, ...ts.configs.recommended],
    languageOptions: { globals: { ...globals.browser, ...globals.worker } },
    rules: { "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }] } },
  { files: ["src/client/**/*.tsx"], plugins: { "react-hooks": hooks },
    rules: { "react-hooks/rules-of-hooks": "error", "react-hooks/exhaustive-deps": "error" } },
);
