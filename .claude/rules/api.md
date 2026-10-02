---
paths:
  - "apps/api/app/api/**/*.py"
  - "apps/api/app/schemas/**/*.py"
  - "apps/api/app/core/deps.py"
  - "apps/api/app/core/errors.py"
  - "apps/api/app/core/middleware.py"
  - "apps/api/app/main.py"
---

# API

Before designing or changing an endpoint, a schema, an error or a middleware, read
`docs/API_GUIDELINES.md` in full, once per session, and follow it. It condenses Microsoft's and
Postman's REST guidance and two FastAPI production guides, marks each practice as in place, to
adopt, or deliberately not here, and ends with a checklist for a new endpoint.
