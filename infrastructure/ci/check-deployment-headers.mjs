/**
 * The frontend's security response headers, checked against both deploy configs.
 *
 * Vercel reads whichever `vercel.json` matches the project's Root Directory, and
 * this repository carries two so the build works from either (docs/DEPLOYMENT.md
 * section 3). The headers were in only one of them: a project configured with an
 * empty Root Directory shipped the frontend with no CSP and no HSTS, and the
 * only symptom was the absence of something.
 *
 * Checked here rather than in a vitest file because the artifacts are
 * repository-level configuration, not application source -- the same reason the
 * Supabase role template's placeholder is checked by a CI step. Run it directly:
 *
 *     node infrastructure/ci/check-deployment-headers.mjs
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const CONFIGS = ["vercel.json", "apps/web/vercel.json"];

// Every header the frontend is expected to answer with. Adding one to a config
// without adding it here is allowed; dropping one from either config is not.
const REQUIRED = [
  "Content-Security-Policy",
  "Strict-Transport-Security",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
];

const root = new URL("../../", import.meta.url);
const problems = [];

function catchAllHeaders(path) {
  const config = JSON.parse(readFileSync(fileURLToPath(new URL(path, root)), "utf8"));
  const rule = (config.headers ?? []).find((entry) => entry.source === "/(.*)");
  if (!rule) {
    problems.push(`${path} has no catch-all header rule, so it serves no security headers.`);
    return null;
  }
  return rule.headers;
}

const [first, second] = CONFIGS.map(catchAllHeaders);

for (const [path, headers] of CONFIGS.map((path, index) => [path, [first, second][index]])) {
  if (!headers) continue;
  const keys = headers.map((header) => header.key);
  for (const required of REQUIRED) {
    if (!keys.includes(required)) problems.push(`${path} is missing ${required}.`);
  }
}

if (first && second && JSON.stringify(first) !== JSON.stringify(second)) {
  problems.push(
    `${CONFIGS[0]} and ${CONFIGS[1]} do not send the same headers. Whichever Root ` +
      "Directory the Vercel project uses has to produce the same response.",
  );
}

if (problems.length > 0) {
  for (const problem of problems) {
    console.error(`::error file=vercel.json::${problem}`);
  }
  process.exit(1);
}

console.log(`Deployment headers match across ${CONFIGS.join(" and ")}.`);
