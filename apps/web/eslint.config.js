import js from "@eslint/js";
import eslintComments from "@eslint-community/eslint-plugin-eslint-comments/configs";
import globals from "globals";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

/**
 * The TypeScript standard as checks (docs/TYPESCRIPT_GUIDELINES.md, DECISIONS.md §193).
 *
 * typescript-eslint's strict and stylistic sets, type-aware, so the rules that
 * need the type checker -- floating promises, unsafe `any`, needless assertions
 * -- can see types. A rule that is wrong for this codebase is turned off or
 * tuned below with its reason, never the set.
 *
 * What the code already broke when a rule landed is recorded in
 * eslint-suppressions.json (`eslint --suppress-all`): only new violations fail,
 * and a fixed one must be pruned (`npm run lint:prune`), so the file only
 * shrinks. Never add to it by hand.
 *
 * History: there was once no config here at all, and `npm run lint` pointed at a
 * missing file for months because nothing ran it. CI runs it now.
 */
export default tseslint.config(
  {
    ignores: ["dist", "node_modules", "coverage"],
  },
  {
    linterOptions: {
      // A disable comment that no longer disables anything is an error, so
      // they do not outlive the code they excused.
      reportUnusedDisableDirectives: "error",
    },
  },
  {
    // Every disable comment names its rule and says why (`-- reason`).
    ...eslintComments.recommended,
    rules: {
      ...eslintComments.recommended.rules,
      "@eslint-community/eslint-comments/require-description": "error",
      "@eslint-community/eslint-comments/no-unlimited-disable": "error",
    },
  },

  // --- TypeScript ----------------------------------------------------------
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.strictTypeChecked,
      ...tseslint.configs.stylisticTypeChecked,
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: { allowDefaultProject: ["vite.config.ts"] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      "jsx-a11y": jsxA11y,
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // The strict set: a rule that fires on a false positive is turned down
      // below with its reason, never the set (DECISIONS.md §155).
      ...jsxA11y.flatConfigs.strict.rules,
      // A key handler on a container is where the graph canvases and the
      // route navigator hear the arrow keys bubbling up from the focused box
      // inside -- the element answering them is already a tab stop. A click
      // on a bare `div` is the hazard these rules exist for, so they still
      // watch the pointer.
      "jsx-a11y/no-static-element-interactions": [
        "error",
        { handlers: ["onClick", "onMouseDown", "onMouseUp"] },
      ],
      "jsx-a11y/no-noninteractive-element-interactions": [
        "error",
        { handlers: ["onClick", "onMouseDown", "onMouseUp"] },
      ],

      // Vite's fast refresh only works when a module exports components and
      // nothing else. A warning rather than an error: several pages
      // legitimately export a helper beside their component, and breaking the
      // build over a development-time convenience would be the wrong trade.
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],

      // --- Language (Google TS style guide) -------------------------------
      eqeqeq: ["error", "always", { null: "ignore" }],
      "no-console": "error",
      "no-var": "error",
      "prefer-const": "error",
      "no-param-reassign": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "TSEnumDeclaration",
          message:
            "Use a union of string literals (`type Severity = 'HIGH' | 'LOW'`), not an enum.",
        },
        {
          selector: "ExportDefaultDeclaration",
          message:
            "Use a named export. Only a module loaded with lazy()/import() may default-export.",
        },
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Render text as children. Raw HTML is an XSS sink.",
        },
        {
          selector:
            "JSXOpeningElement[name.name='Button'] > JSXAttribute[name.name='render'] JSXOpeningElement[name.name='Link']",
          message:
            "A navigation styled as a button is a Link with buttonVariants() (DECISIONS.md §31).",
        },
        {
          selector: "Literal[value=/\\btext-\\[\\d+px\\]/]",
          message:
            "Use a step of the type scale (text-caption, text-body...), not text-[Npx] (§166).",
        },
        {
          selector: "TemplateElement[value.raw=/\\btext-\\[\\d+px\\]/]",
          message:
            "Use a step of the type scale (text-caption, text-body...), not text-[Npx] (§166).",
        },
      ],

      // --- Types -----------------------------------------------------------
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      // `as Foo` on an object literal hides a missing or misspelled field; a
      // `: Foo` annotation reports it.
      "@typescript-eslint/consistent-type-assertions": [
        "error",
        { assertionStyle: "as", objectLiteralTypeAssertions: "never" },
      ],
      // The type checker already fails the build on an unused local
      // (`noUnusedLocals`); two tools reporting one thing is noise.
      "@typescript-eslint/no-unused-vars": "off",

      // --- Tuned for React -------------------------------------------------
      // `onClick={() => setOpen(false)}` returns the setter's void; the rule
      // would put braces on every handler in the app for no reader's benefit.
      "@typescript-eslint/no-confusing-void-expression": "off",
      // Counts and percentages are the numbers this UI prints.
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // A no-op default (`onClose = () => {}`) is an arrow on purpose.
      "@typescript-eslint/no-empty-function": ["error", { allow: ["arrowFunctions"] }],
      // Without noUncheckedIndexedAccess the checker believes `items[i]` is
      // always defined, so this rule calls the guard on it "unnecessary" and
      // would talk people out of a real check. On once that flag is (§193).
      "@typescript-eslint/no-unnecessary-condition": "off",
    },
  },
  {
    // A module loaded with lazy() or import() needs a default export.
    files: [
      "src/components/graph/EstateCanvas.tsx",
      "src/components/graph/NeighborhoodCanvas.tsx",
      "src/components/graph/RouteMapCanvas.tsx",
      "src/lib/motionFeatures.ts",
      "vite.config.ts",
    ],
    rules: { "no-restricted-syntax": "off" },
  },
  {
    // shadcn components are vendored source: they are ours to edit, but they
    // arrive from the registry in the registry's own style, and restyling them
    // on arrival would make every later `shadcn add --diff` unreadable. They
    // keep the correctness rules and drop the stylistic ones.
    files: ["src/components/ui/**"],
    extends: [tseslint.configs.disableTypeChecked],
    rules: {
      "react-refresh/only-export-components": "off",
      "@typescript-eslint/no-empty-object-type": "off",
      "@typescript-eslint/consistent-type-definitions": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      // Props arrive spread, so the rule cannot see the `htmlFor` a `Label`
      // is given or the text a `PaginationLink` wraps.
      "jsx-a11y/label-has-associated-control": "off",
      "jsx-a11y/anchor-has-content": "off",
      // The input group's addon focuses its input on a click: a pointer
      // convenience, when the input is itself the tab stop.
      "jsx-a11y/click-events-have-key-events": "off",
      "jsx-a11y/no-noninteractive-element-interactions": "off",
    },
  },
  {
    // A provider and the hook that reads it belong in one file: splitting them
    // to satisfy a development-time refresh optimisation would put the context
    // and its only consumer in different modules for no reader's benefit.
    files: ["src/i18n/index.tsx", "src/components/scans/ScanWizardProvider.tsx"],
    rules: { "react-refresh/only-export-components": "off" },
  },
  {
    files: ["**/*.test.{ts,tsx}", "src/test/**"],
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
    },
    rules: {
      // A test may assert what it just arranged.
      "@typescript-eslint/no-non-null-assertion": "off",
      "no-console": "off",
    },
  },

  // --- JavaScript (config files, scripts, the pre-paint theme script) -----
  {
    files: ["**/*.{js,mjs}"],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.node },
    },
    rules: {
      eqeqeq: ["error", "always", { null: "ignore" }],
      "no-var": "error",
      "prefer-const": "error",
    },
  },
  {
    // Runs as a classic script in the page before React, to set the theme
    // without a flash.
    files: ["public/**/*.js"],
    languageOptions: { sourceType: "script", globals: { ...globals.browser } },
  },
);
