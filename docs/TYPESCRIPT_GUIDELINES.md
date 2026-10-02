# TypeScript guidelines

How TypeScript and JavaScript are written in `apps/web`, the React single-page app. It condenses
two sources, and where they disagree with each other or with this codebase, it says which one
wins and why:

- the [Google TypeScript style guide](https://google.github.io/styleguide/tsguide.html) (also
  published as [ts.dev/style](https://ts.dev/style/)), for the language rules;
- [W3Schools' TypeScript best practices](https://www.w3schools.com/typescript/typescript_best_practices.php),
  for compiler configuration, null handling and async code.

Consistency with the code around you beats any single rule here. The UI conventions in CLAUDE.md
(tokens, the type scale, icons, primitives, motion, accessibility) apply on top of this document.

Each rule is tagged with how it is held:

- **`[eslint rule]`**: ESLint fails the commit hook and CI (`apps/web/eslint.config.js`). Rules
  are type-aware: they see the types the compiler sees.
- **`[tsc flag]`**: the compiler fails the build (`apps/web/tsconfig.json`).
- **`[prettier]`**: Prettier formats it; never argue with the formatter in review.
- **`[review]`**: no tool can see it, so review does.

Code that broke a rule when the rule landed is listed in `apps/web/eslint-suppressions.json`. New
code is held to every rule; the listed violations are fixed over time and the list only shrinks
(DECISIONS.md §193).

## 1. Compiler

`strict` plus `noUnusedLocals`, `noUnusedParameters`, `noFallthroughCasesInSwitch`,
`noImplicitOverride`, `noImplicitReturns` and `verbatimModuleSyntax`. `[tsc flag]`

- Never write `@ts-ignore` or `@ts-nocheck`. In a test, `@ts-expect-error` is allowed with a
  reason, to prove a type error. `[eslint ban-ts-comment]`
- `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` are next (105 and 42 errors today).
  Until then, treat `items[i]` and `record[key]` as possibly `undefined` and check. `[review]`

## 2. Files and modules

- Use ES modules only: no `namespace`, no `require`, no `/// <reference>`. `[eslint
  no-namespace, no-require-imports, triple-slash-reference]`
- Use named exports only. A module loaded with `lazy()` or `import()` is the one exception, listed
  in the ESLint config. `[eslint no-restricted-syntax]`
- Never export a mutable binding (`export let`). Export a function that reads it. `[review]`
- Export only what another module uses. `[review]`
- Import within the app through the `@/` alias (`@/lib/format`). Use `./` only for a sibling in
  the same folder. `[review]`
- A type-only import says so: `import type { Finding } from "@/lib/types"`. `[eslint
  consistent-type-imports, tsc verbatimModuleSyntax]`
- No barrel `index.ts` files that re-export a folder. Import the module that defines the thing.
  `[review]`
- File names: `PascalCase.tsx` for a file whose main export is a component; `camelCase.ts` for
  everything else; tests in `__tests__/` as `name.test.ts(x)`. `[review]`

## 3. Naming

| Kind | Style | Example |
|---|---|---|
| Component, class, interface, type, type parameter | `UpperCamelCase` | `RouteNavigator`, `ScanDetail`, `T` |
| Variable, function, parameter, property, hook | `lowerCamelCase` | `formatDate`, `useLiveScan` |
| Module-level constant, never reassigned | `CONSTANT_CASE` | `MAX_REASON`, `IN_FLIGHT` |
| Props of a component | `<Component>Props` | `RouteMapCanvasProps` |

- Treat acronyms as words: `loadHttpUrl`, `scanId`, not `loadHTTPURL`. `[review]`
- No `I` prefix on interfaces, no `_` prefix for "private". `[review]`
- A name says what a thing is. Single letters only in scopes of a few lines. `[review]`
- Hooks start with `use`. `[eslint react-hooks]`

## 4. Types

- Let inference work for locals and obvious returns. Annotate a function's parameters, an exported
  function's return when it isn't obvious, and anything whose inferred type would be too wide.
  `[review]`
- Use `interface` for object shapes. Use `type` for unions, tuples, mapped and conditional types.
  `[eslint consistent-type-definitions]` (A shape that must satisfy `Record<string, unknown>`,
  such as React Flow edge data, stays a `type` with a reasoned disable.)
- Never use `any`. At a boundary (JSON, `catch`, a third-party callback), take `unknown` and
  narrow it. `[eslint no-explicit-any, no-unsafe-*]`
- Never use `{}`, `Object`, `String`, `Number` or `Boolean` as types. Use `unknown`, `object`,
  `Record<K, V>` or the lowercase primitives. `[eslint no-empty-object-type,
  no-wrapper-object-types]`
- No `enum`. Use a union of string literals (`type Severity = "CRITICAL" | "HIGH"`), with an
  `as const` array when the values are also needed at runtime. `[eslint no-restricted-syntax]`
- Write arrays as `T[]` and `readonly T[]`, never `Array<T>`. `[eslint array-type]`
- Use `readonly` for properties and arrays that are never written after construction.
  `[review]`
- Name a tuple's members, or use an object, when the positions are not self-evident. `[review]`
- Avoid return-type-only generics (`get<T>(): T`). Keep generics a function actually relates.
  `[eslint no-unnecessary-type-parameters]`

## 5. Assertions and narrowing

- Prefer narrowing (`typeof`, `instanceof`, `in`, a type guard `x is T`) to asserting. `[review]`
- When an assertion is necessary, write `as T` with a comment saying why it is true. Never use
  `<T>x`. `[eslint consistent-type-assertions]`
- Never assert an object literal. Annotate it (`const x: T = {...}`), so a missing or misspelled
  field is reported. `[eslint consistent-type-assertions]`
- Don't use `!` non-null assertions in app code. Check, or restructure so the type says it.
  Tests may use `!` on what they just arranged. `[eslint no-non-null-assertion]`
- Remove an assertion the compiler already knows. `[eslint no-unnecessary-type-assertion]`

## 6. Null and undefined

- Use `undefined` for "not given" (optional props and parameters, `?:`), and `null` where the API
  sends `null`. Don't add `| null` or `| undefined` inside a type alias; add it where it is used.
  `[review]`
- Prefer `?:` to `| undefined` in interfaces and parameters. `[review]`
- Use `??` for a default and `?.` to reach through a possibly-absent value. Use `||` only when
  `0`, `""` and `false` should fall back too, and say so. `[eslint prefer-nullish-coalescing,
  prefer-optional-chain]`
- Compare with `===` and `!==`. `== null` is allowed, as the one check that covers `null` and
  `undefined` together. `[eslint eqeqeq]`

## 7. Functions

- Name module-level functions and components with `function` declarations. Use arrow functions for
  callbacks and nested helpers. Never use `function` expressions. `[review]`
- No arrow-function class properties and no `bind`; the app has one class, `ErrorBoundary`.
  `[review]`
- Keep parameters few: past three, or with any optional boolean, take an options object.
  `[review]`
- Reassign neither parameters nor their properties; copy. `[eslint no-param-reassign]`
- Use rest and spread, never `arguments` or `.apply`. `[eslint prefer-rest-params,
  prefer-spread]`
- A default parameter has no side effects. `[review]`

## 8. Variables and control flow

- `const` by default, `let` only when reassigned, never `var`. One declaration per statement.
  `[eslint prefer-const, no-var]`
- Iterate arrays with `for...of` or array methods; objects with `Object.entries/keys/values`.
  Never use `for...in`. `[eslint no-for-in-array; review]`
- A `switch` over a union covers every member, so adding a member is an error where it is
  unhandled. `[eslint switch-exhaustiveness-check, tsc noFallthroughCasesInSwitch]`
- Use template literals to build strings with values in them. Interpolate numbers and strings,
  never objects. `[eslint restrict-template-expressions, no-base-to-string]`
- Parse numbers with `Number()` and check `Number.isFinite`. Use `parseInt` only with a radix and
  for a non-decimal string. Never use unary `+`. `[review]`
- Use `.includes()`, `.startsWith()` and `.endsWith()` rather than `indexOf` comparisons. `[eslint
  prefer-includes, prefer-string-starts-ends-with]`

## 9. Errors

- Throw only `Error` (or a subclass), created with `new`. `[eslint only-throw-error]`
- `catch (error)` binds `unknown`. Narrow it (`error instanceof Error`) before reading it.
  `[tsc useUnknownInCatchVariables]`
- Keep `try` blocks around only the call that can fail. An empty `catch` says why it is empty.
  `[eslint no-empty; review]`
- A failure the user can act on is shown in the UI. Don't swallow it, and don't `console.log` it.
  The error boundary is the one place that writes to the console. `[eslint no-console]`

## 10. Async code

- Every promise is awaited, returned, or handled with `.catch`. A deliberate fire-and-forget says
  so with `void`: `void flow.fitView()`. `[eslint no-floating-promises]`
- Don't pass an async function where a void callback is expected (an `onClick` that returns a
  promise hides its rejection). Wrap it: `onClick={() => void save()}`. `[eslint
  no-misused-promises]`
- An `async` function awaits something; otherwise drop `async`. `[eslint require-await]`
- Run independent requests together with `Promise.all`, not one `await` after another.
  `[review]`
- Server state lives in TanStack Query (`useQuery`, `useMutation`), not in `useEffect` plus
  `useState`. `[review]`

## 11. React

- Write components as `function Name(props: NameProps)`, never `React.FC`. Destructure props in the
  signature when it reads better. `[review]`
- Follow the rules of hooks, and list every dependency. Excluding one takes a disable comment
  saying why. `[eslint react-hooks]`
- Don't sync state with `useEffect`. Derive it during render, or key the component to reset it.
  `[review]`
- Use a stable, unique `key` from the data, never the array index for a list that reorders.
  `[review]`
- A component file exports components only, so fast refresh works. `[eslint
  react-refresh/only-export-components]`
- Never `dangerouslySetInnerHTML`. `[eslint no-restricted-syntax]`
- Accessibility is checked twice: jsx-a11y strict, and axe on every test's final render (§155).
  `[eslint jsx-a11y]`

## 12. Comments

- Use `/** JSDoc */` for what a caller needs (a component's purpose, an exported function's
  contract), and `//` for why the code is shaped this way. Never restate the code. `[review]`
- Don't put types in JSDoc (`@param {string}`); the signature has them. `[review]`
- Write comments as full sentences, and cite `DECISIONS.md §N` rather than re-arguing a decision.
  `[review]`
- A disable comment names one rule and says why after `--`:
  `// eslint-disable-next-line react-hooks/exhaustive-deps -- once per canvas.` `[eslint
  eslint-comments/require-description, no-unlimited-disable]`
- A disable that no longer disables anything is an error. `[eslint
  reportUnusedDisableDirectives]`

## 13. Formatting

Prettier, at its defaults with 100 columns: double quotes, semicolons, trailing commas, two-space
indentation. `[prettier]`

## 14. Disallowed

- `eval`, `new Function`, `with`, `debugger`. `[eslint no-implied-eval, no-with, no-debugger;
  eval and new Function: review]`
- Wrapper objects (`new String()`), and the `Array()` and `Object()` constructors. `[eslint
  no-array-constructor; the rest: review]`
- Modifying built-in prototypes, or adding to `window`. `[review]`
- `text-[Npx]` font sizes (§166) and `Button render={<Link/>}` (§31). `[eslint
  no-restricted-syntax]`

## 15. JavaScript files

Configuration files, `scripts/*.mjs` and `public/theme-init.js` follow the same rules where they
apply: ES modules, `const`/`let`, `===`. `public/theme-init.js` runs as a classic script before
React; keep it small, self-contained in one function, and in step with `src/lib/theme.ts`.
`[eslint; review]`

---

## Where these depart from the sources

| Topic | Google | W3Schools | Here | Why |
|---|---|---|---|---|
| Quotes | single | — | double | Prettier's default; one less setting to argue about |
| Import paths | relative | — | `@/` alias, `./` for siblings | Moving a file doesn't rewrite its imports; the alias is in CLAUDE.md |
| File names | `snake_case` | `kebab-case` | `PascalCase.tsx` components, `camelCase.ts` else | The established layout of `apps/web`; renames would churn history |
| Barrel files | — | recommended | no | They hide where a thing lives and defeat lazy-loading |
| Default exports | never | — | only for `lazy()`/`import()` | React.lazy requires a default export |
| Enums | plain `enum`, never `const enum` | union literals | union literals | Erase to nothing; match the API's string values |
| Array type | `T[]` simple, `Array<T>` complex | — | `T[]` always | typescript-eslint's default; one form to read |
| Return types | optional | always for public functions | when not obvious | Inference is exact; annotate where it helps a reader |
| `#private` fields | never | — | not applicable | The app has one class (`ErrorBoundary`) |
| JSDoc | required on exports | — | when a caller needs it | Most exports are components whose props interface documents them |
