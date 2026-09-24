# 🔐 Code Secret Handler

A **language-agnostic CLI tool** that scans any codebase for hardcoded secrets, lists them with full context, moves them to a `.env` file, and rewrites source files with the correct environment variable accessor for each language.

---

## Features

- 🔍 **Deep scanning** — 179+ secret types detected across 10 rule categories (AWS, GCP, Azure, GitHub, Stripe, Twilio, OpenAI, Anthropic, Discord, Telegram, Supabase, JWT, SSH keys, database URIs, SMTP, and many more)
- 🌐 **Language-aware rewriting** — auto-detects file language and uses the correct env-var syntax:
  - `process.env.KEY` (JavaScript/TypeScript)
  - `os.environ.get('KEY')` (Python)
  - `System.getenv("KEY")` (Java/Kotlin)
  - `os.Getenv("KEY")` (Go)
  - `ENV['KEY']` (Ruby)
  - `getenv('KEY')` (PHP)
  - `Environment.GetEnvironmentVariable("KEY")` (C#)
  - `std::env::var("KEY")` (Rust)
  - `$KEY` / `$env:KEY` (Shell/PowerShell)
  - `${KEY}` (YAML, TOML, properties files)
- 📋 **Multiple report formats** — console (colored), JSON, CSV, Markdown
- 🔒 **Collision-safe** — appends `_2`, `_3`, etc. for duplicate env key names
- 🧠 **Respects `.gitignore`** — only scans tracked files, skips `node_modules`, `dist`, etc.
- 🛡️ **Interactive** — asks before making any changes, with backup option
- 🔍 **Dry-run mode** — scan and report without modifying anything

---

## Installation

```bash
# Run directly with npx (no install needed)
npx code-secret-handler ./my-project

# Or install globally
npm install -g code-secret-handler
csh ./my-project
```

---

## Usage

```bash
csh [target-dir] [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `[target-dir]` | Directory to scan | `.` (current dir) |
| `-r, --report <format>` | Report format: `console` \| `json` \| `csv` \| `markdown` | `console` |
| `-o, --output <file>` | Report output file path | Auto-derived |
| `-e, --env-file <path>` | Target `.env` file path | `./.env` |
| `--dry-run` | Scan only — no file modifications | `false` |
| `--no-rewrite` | Write `.env` but skip source-file rewriting | `false` |
| `-v, --version` | Show version | |
| `-h, --help` | Show help | |

### Examples

```bash
# Scan current directory (interactive)
csh .

# Dry run — see what would be found without changes
csh ./my-app --dry-run

# Write Markdown report to a file
csh ./my-app -r markdown -o security-report.md

# Use a custom .env file location
csh ./my-app -e config/.env

# Write .env but do NOT rewrite source files
csh ./my-app --no-rewrite

# JSON report
csh ./my-app -r json -o findings.json

# CSV report for spreadsheet import
csh ./my-app -r csv
```

---

## How It Works

```
CLI args
  └─► File Walker (respects .gitignore)
        └─► Detector (179+ regex rules, line-by-line)
              └─► Findings  { file, line, col, type, rawValue, envKey }
                    ├─► Reporter (console/json/csv/markdown)
                    └─► [Interactive confirmation]
                          ├─► Env Writer  →  .env
                          └─► Rewriter    →  patched source files
```

### Detection Rules

| Category | Rules | Examples |
|----------|-------|----------|
| AWS | 10 | Access Key ID (`AKIA…`), Secret Key, Session Token, ARN, S3 bucket, MWS key, CloudFront |
| GCP | 11 | API Key (`AIza…`), OAuth Client, Service Account, Maps, reCAPTCHA, Firebase DB URL |
| Azure | 8 | Storage connection strings, SAS tokens, Service Bus, CosmosDB, Client/Tenant ID |
| GitHub | 4 | `ghp_`, `gho_`, `ghs_`, `github_pat_` tokens |
| GitLab | 2 | `glpat-` Personal Access Tokens, Runner registration tokens |
| Stripe | 3 | `sk_live_`, `sk_test_`, `rk_live_`, `whsec_` webhook secrets |
| Twilio | 3 | Account SID, Auth Token, API Key (`SK…`) |
| Slack | 3 | `xoxb-`/`xoxp-` tokens, webhook URLs, signing secrets |
| JWT / Auth | 11 | JWT secrets, session, NextAuth, Flask, Rails `secret_key_base`, CSRF, OAuth2 |
| SSH / PEM | 10 | RSA, EC, DSA, OpenSSH, PGP private key blocks, PKCS12 |
| Database | 19 | PostgreSQL, MySQL, MongoDB, Redis, MSSQL, Elasticsearch, RabbitMQ, Cassandra, Oracle, CockroachDB, Neo4j, InfluxDB, Kafka |
| Network | 12 | SMTP, proxy URLs, LDAP, CI/CD deploy tokens, Apple APNs, webhook URLs |
| AI / ML | 6 | OpenAI (`sk-`), Anthropic (`sk-ant-`), Hugging Face (`hf_`), Pinecone, Cohere, Replicate (`r8_`) |
| Payments | 5 | Square (`EAA…`), Razorpay, Braintree, Plaid, PayPal |
| SaaS | 8 | Notion (`secret_`), Linear (`lin_api_`), Airtable, HubSpot, Zendesk, Intercom, Jira, PagerDuty |
| DevOps | 7 | Vercel, DigitalOcean, Terraform Cloud, HashiCorp Vault, Confluent, Docker Hub, Heroku |
| Analytics | 8 | Amplitude, Mixpanel, Segment, New Relic (`NRAK-`), Datadog, Dynatrace, Grafana, Sentry |
| Generic | 21 | API keys/secrets, passwords, bearer tokens, HMAC keys, webhook secrets, license keys, connection strings |
| Other | 16 | Cloudflare, Cloudinary, Algolia, Mapbox, Shopify, Auth0, Okta, Firebase, LaunchDarkly, Discord, Telegram, Mailgun, Mailchimp, SendGrid, NPM, Pusher |

---

## After Running

1. **Verify** the `.env` file was created with the correct values.
2. **Add `.env` to `.gitignore`** — the tool reminds you, but please double-check!
3. **Rotate secrets** that may have been committed to Git history previously.
4. **Review** modified source files before committing.
5. **Share `.env.example`** (with placeholder values) with your team.

---

## Development

```bash
git clone <repo>
cd code-secret-handler
npm install

# Run in dev mode
npm run dev -- ./path/to/scan

# Build
npm run build

# Type-check
npm run lint
```

---

## Telemetry

`code-secret-handler` collects **anonymous usage telemetry** to help the author monitor license compliance and understand how the tool is being used.

### What is collected

| Data | Example |
|------|---------|
| Tool version | `1.0.0` |
| OS platform | `linux`, `darwin`, `win32` |
| Node.js version | `v20.11.0` |
| Git remote URL | `https://github.com/owner/repo` |
| Repo owner & name | `owner`, `repo` |
| Git platform | `github`, `gitlab`, `bitbucket` |
| Account type | `Organization` or `User` |
| License key provided | `true` / `false` |
| Timestamp | ISO 8601 |

### What is NOT collected

- ❌ Source code or file contents
- ❌ Secret values or credentials
- ❌ Personal identifiable information
- ❌ Anything beyond the fields listed above

### Opt out

Set `CSH_TELEMETRY=0` in your environment to disable all telemetry:

```bash
CSH_TELEMETRY=0 csh ./my-project
# or permanently in your shell profile:
export CSH_TELEMETRY=0
```

---

## License

**PolyForm Noncommercial License 1.0.0**
Copyright (c) 2024 Vic — vic.grambo@gmail.com

### ✅ Free for

- Individual developers for personal projects, learning, research, or hobby use
- Non-profit organizations, educational institutions, public research organizations, and government institutions

### ❌ Not free for

- Companies, startups, agencies, or any for-profit organization
- Any use that directly or indirectly generates revenue or commercial advantage
- Running the tool within a commercial CI/CD pipeline or product

### 💼 Commercial licensing

If you represent an organization or wish to use this tool commercially, please contact:

**vic.grambo@gmail.com**

Commercial licensees receive a license key. Set it as an environment variable before running the tool:

```bash
CSH_LICENSE_KEY=<your-key> csh ./my-project
```

The full license text is available in the [LICENSE](./LICENSE) file.
