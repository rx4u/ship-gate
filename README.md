# Ship Gate

Pre-production audit skill for Claude Code. Scans your codebase across
8 categories and blocks shipping until critical issues are resolved.

**80+ checks. Stack-agnostic. Zero dependencies.**

---

## Why

Shipping solo means no pull request reviews, no pre-deploy sign-off,
no one to catch the exposed API key or the Supabase table with RLS
disabled before it hits production.

Ship gate is a pre-deploy scanner. It covers 8 categories: security,
database, deployment, code quality, dependencies, AI/LLM, frontend,
and observability. Flags what is broken. Blocks the deploy until you
fix it.

89 checks. No external dependencies. Runs in seconds.

---

## What It Checks

| Category | Checks | Examples |
|----------|--------|---------|
| **Security** | 18 | API keys in frontend, CORS wildcard, missing auth, CSRF, JWT issues |
| **Database** | 12 | SQL injection, missing RLS (Supabase), service_role in client code |
| **Deployment** | 13 | Missing health check, no structured logging, SSL, rollback plan |
| **Code Quality** | 14 | console.log in prod, empty catch blocks, TODO-auth patterns |
| **AI/LLM Security** | 8 | System prompt leakage, LLM keys in frontend, no rate limiting |
| **Dependencies** | 7 | Wildcard versions, git dependencies, suspicious postinstall |
| **Frontend** | 10 | Missing meta tags, no 404 page, images without alt text |
| **Observability** | 7 | No error monitoring, no structured logging, no uptime checks |

Each check is classified as:
- **CRITICAL**: must fix before shipping
- **HIGH**: should fix before shipping
- **ADVISORY**: recommended but not blocking

---

## Install

### Claude Code Plugin (recommended)

```bash
claude plugin add github:rx4u/ship-gate
```

### Manual Install

```bash
git clone https://github.com/rx4u/ship-gate.git
cp -r ship-gate ~/.claude/skills/
```

### Skills CLI

```bash
npx agent-skills-cli add rx4u/ship-gate
```

---

## Usage

Say any of these to Claude Code:

- "run the ship gate"
- "am I ready to ship?"
- "pre-launch audit"
- "can I deploy?"
- "preflight check"

Or just say "push to production" and Claude will intercept and ask
if you have run the ship gate first.

### Example Output

```
SHIP GATE REPORT
================
Stack: Next.js + Supabase + Vercel
Scan time: 12s

CRITICAL (3 items, must fix)
  FAIL  [SEC-01] API key found in src/lib/api.ts:14
  FAIL  [DB-07] RLS not enabled on "profiles" table
  FAIL  [SEC-05] No CSRF protection on /api/checkout

HIGH (5 items, should fix)
  FAIL  [CODE-01] 12 console.log statements in production code
  FAIL  [CODE-03] Empty catch block in src/utils/auth.ts:45
  FAIL  [DEP-04] 3 critical npm audit vulnerabilities
  FAIL  [DEPLOY-05] No rollback plan documented
  MANUAL [DEPLOY-06] Staging test not confirmed

ADVISORY (4 items, recommended)
  FAIL  [FE-01] Missing OG meta tags
  FAIL  [FE-03] No custom 404 page
  PASS  [OBS-01] Error monitoring configured
  SKIP  [AI-01] No AI/LLM usage detected

VERDICT: DO NOT SHIP (3 critical issues)
Fix critical items and re-run.
```

---

## How It Works

1. **Detects your stack** by scanning package.json, config files, and
   project structure
2. **Runs automated checks** using grep and pattern matching (no
   external tools required, npm audit optional)
3. **Presents manual checks** for items that cannot be automated
   (backup tested, staging verified, rollback plan exists)
4. **Reports a verdict**: CLEAR TO SHIP, SHIP WITH CAUTION, or
   DO NOT SHIP

---

## Supported Stacks

Ship Gate is stack-agnostic. It detects your stack and runs relevant
checks automatically.

Tested with:
- Next.js, React, Vue, Svelte, Astro
- Supabase, PostgreSQL, MongoDB, Firebase
- Vercel, Netlify, AWS, Railway, Fly.io, Docker
- Python (Django, Flask, FastAPI)
- Node.js (Express, Fastify, Hono)

---

## Contributing

Found a check that is missing? A pattern that produces false positives?

1. Fork this repo
2. Edit `references/checks.md` to add or improve checks
3. Edit `references/patterns.md` to add or improve detection patterns
4. Submit a PR

All checks need: an ID, description, detection method, severity, and
remediation guidance.

---


## License

MIT

---

**Built by [Rajaraman Arumugam](https://linkedin.com/in/dsgnr)**
Design. AI. Product. Leadership.
