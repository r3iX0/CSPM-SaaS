---
paths:
  - "apps/web/**/*.ts"
  - "apps/web/**/*.tsx"
  - "apps/web/**/*.js"
  - "apps/web/**/*.mjs"
  - "infrastructure/ci/*.mjs"
---

# TypeScript

Before writing or reviewing TypeScript or JavaScript in this repository, read
`docs/TYPESCRIPT_GUIDELINES.md` in full, once per session, and follow it. It condenses the Google
TypeScript style guide and W3Schools' best practices, and records where this codebase departs
from them and why. `apps/web/eslint.config.js` and `tsconfig.json` enforce the mechanical part on
commit and in CI; never add to `eslint-suppressions.json` by hand.
