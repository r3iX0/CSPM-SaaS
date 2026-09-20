"""Generate OpenAPI specification and interactive HTML documentation for CloudGuard API.

Exports the live FastAPI OpenAPI 3.1.0 schema directly from route definitions and
schemas, ensuring documentation never drifts from implementation.

Usage:
    python apps/api/scripts/generate_openapi.py
    python apps/api/scripts/generate_openapi.py --check
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from pathlib import Path
from typing import Any

# Ensure test mode for configuration if unset, preventing startup check failures
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SUPABASE_JWT_SECRET", "doc-gen-secret")
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://cloudguard_app:x@localhost:5432/cg"
)
os.environ.setdefault(
    "DATABASE_OWNER_URL", "postgresql+asyncpg://cloudguard:x@localhost:5432/cg"
)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_JSON_OUTPUT = REPO_ROOT / "docs" / "api" / "openapi.json"
DEFAULT_HTML_OUTPUT = REPO_ROOT / "docs" / "api" / "index.html"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CloudGuard API Reference & Interactive Playground</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body {
      margin: 0;
      padding: 0;
      background-color: #0d1117;
      color: #c9d1d9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .header {
      background: #161b22;
      border-bottom: 1px solid #30363d;
      padding: 16px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .header h1 {
      margin: 0;
      font-size: 1.25rem;
      font-weight: 600;
      color: #58a6ff;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .header .meta {
      font-size: 0.875rem;
      color: #8b949e;
    }
    .header a {
      color: #58a6ff;
      text-decoration: none;
    }
    .header a:hover {
      text-decoration: underline;
    }
    .badge {
      font-size: 0.75rem;
      background: #238636;
      color: #fff;
      padding: 2px 8px;
      border-radius: 12px;
    }
    /* Swagger UI Dark Mode Adaptations */
    .swagger-ui {
      filter: invert(88%) hue-rotate(180deg);
      padding: 20px;
    }
    .swagger-ui .topbar {
      display: none;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>
      <span>🛡️ CloudGuard API</span>
      <span class="badge">v0.1.0</span>
    </h1>
    <div class="meta">
      Auto-generated from FastAPI &bull;
      <a href="./openapi.json" download="openapi.json">Download OpenAPI JSON</a> &bull;
      <a href="../API.md">API Design Doc</a>
    </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "./openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>
"""


def generate_openapi_spec() -> dict[str, Any]:
    """Import the FastAPI application and generate its OpenAPI schema."""
    api_dir = REPO_ROOT / "apps" / "api"
    if str(api_dir) not in sys.path:
        sys.path.insert(0, str(api_dir))

    from app.main import app

    schema: dict[str, Any] = app.openapi()
    return schema


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or check OpenAPI documentation.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if docs/api/openapi.json is up-to-date without overwriting.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=DEFAULT_JSON_OUTPUT,
        help="Target path for openapi.json",
    )
    parser.add_argument(
        "--output-html",
        type=Path,
        default=DEFAULT_HTML_OUTPUT,
        help="Target path for index.html",
    )

    args = parser.parse_args()

    schema = generate_openapi_spec()
    new_json = json.dumps(schema, indent=2) + "\n"

    target_json = args.output_json
    target_html = args.output_html

    if args.check:
        if not target_json.exists():
            print(f"Error: {target_json} does not exist. Run without --check to generate.")
            return 1

        existing_json = target_json.read_text(encoding="utf-8")
        if existing_json != new_json:
            print(f"Error: {target_json} is out of date. Diff:")
            diff = difflib.unified_diff(
                existing_json.splitlines(),
                new_json.splitlines(),
                fromfile="committed openapi.json",
                tofile="generated openapi.json",
                lineterm="",
            )
            for line in list(diff)[:50]:
                print(line)
            print("\nRun `python apps/api/scripts/generate_openapi.py` to regenerate.")
            return 1

        print(f"OK: {target_json} matches current FastAPI code.")
        return 0

    target_json.parent.mkdir(parents=True, exist_ok=True)
    target_json.write_text(new_json, encoding="utf-8")
    print(f"Wrote OpenAPI schema to {target_json} ({len(new_json.encode('utf-8'))} bytes)")

    target_html.parent.mkdir(parents=True, exist_ok=True)
    target_html.write_text(HTML_TEMPLATE, encoding="utf-8")
    print(f"Wrote interactive HTML documentation to {target_html}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
