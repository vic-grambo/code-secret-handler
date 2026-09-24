# 🔐 Hardcoded Secrets Audit Report

**Generated:** 2026-09-24
**Repos Scanned:** `python/`, `js/`, `php/`
**Files Scanned:** 14 source files + 3 `.env` files

---

## 📊 Executive Summary

| Category | Hardcoded Secrets Found |
|---|---|
| 🗄️ Database Passwords (MySQL, MSSQL, Redis, MongoDB, Elasticsearch, Replica) | 14 |
| 🔑 Auth / JWT / Session / OAuth Keys & Tokens | 7 |
| ☁️ Cloud Credentials (AWS, Azure, GCP, Vault, Artifactory) | 8 |
| 💳 Payment Secrets (Stripe, PayPal, Braintree) | 4 |
| 🔗 Integration Keys (SendGrid, PagerDuty, Twilio) | 5 |
| 🐇 Message Queue (RabbitMQ URI + Password) | 6 |
| **TOTAL** | **44** |

---

## ⚠️ Severity Legend

| Icon | Meaning |
|---|---|
| 🚨 | **Critical** — Secret / password / key hardcoded directly in source |
| 🟡 | **Low** — Non-secret value hardcoded (hostname, username, non-sensitive ID) |
| ✅ | **Safe** — Value is read from environment variable |

---

## 🐍 Python Repo (`python/`)

### `python/connections.py`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `MONGODB_URI` | ✅ Safe | via `os.environ.get()` |
| `MONGODB_USERNAME` | ✅ Safe | via `os.environ.get()` |
| `MONGODB_PASSWORD` | ✅ Safe | via `os.environ.get()` |
| `MONGODB_HOST` | ✅ Safe | via `os.environ.get()` |
| `REDIS_HOST` | 🟡 Hostname | `redis-prod.internal.mycompany.com` |
| `REDIS_PASSWORD` | 🚨 **HARDCODED** | `R3d1sS3cr3tP@ssw0rd!` |
| `MYSQL_HOST` | 🟡 Hostname | `mysql-prod.internal.mycompany.com` |
| `MYSQL_USERNAME` | 🟡 Username | `mysql_admin` |
| `MYSQL_PASSWORD` | 🚨 **HARDCODED** | `MySQLSup3rS3cr3t!2024` |
| `RABBITMQ_URI` | 🚨 **HARDCODED** (full URI with credentials) | `amqps://rmq_user:RabbitmqS3cr3t!P%40ss@rabbitmq-prod...` |
| `RABBITMQ_USERNAME` | 🟡 Username | `rmq_user` |
| `RABBITMQ_PASSWORD` | 🚨 **HARDCODED** | `RabbitmqS3cr3t!P@ss` |
| `ELASTICSEARCH_HOST` | 🟡 Hostname | `elasticsearch-prod.internal.mycompany.com` |
| `ELASTICSEARCH_USERNAME` | 🟡 Username | `elastic` |
| `ELASTICSEARCH_PASSWORD` | 🚨 **HARDCODED** | `3l@st1cS3cr3tP@ss!` |
| `ELASTICSEARCH_API_KEY` | 🚨 **HARDCODED** | `ZXMtYXBpLWtleS1pZDplcy1hcGkta2V5LXZhbHVlLXN0cmluZw==` |
| `MSSQL_CONNECTION_STRING` | 🚨 **HARDCODED** (full string with password) | `Server=mssql-prod...Password=MssqlSup3rS3cr3t!2024;...` |
| `MSSQL_USERNAME` | 🟡 Username | `sa` |
| `MSSQL_PASSWORD` | 🚨 **HARDCODED** | `MssqlSup3rS3cr3t!2024` |

### `python/secrets_sample.py`

> All secrets properly read via `os.environ.get(...)` — no hardcoded secrets in source.

---

## 🟨 JS Repo (`js/`)

### `js/connections.js`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `MONGODB_URI` | ✅ Safe | via `process.env` |
| `MONGODB_USERNAME` | ✅ Safe | via `process.env` |
| `MONGODB_PASSWORD` | ✅ Safe | via `process.env` |
| `MONGODB_HOST` | ✅ Safe | via `process.env` |
| `REDIS_HOST` | 🟡 Hostname | `redis-prod.internal.mycompany.com` |
| `REDIS_PASSWORD` | 🚨 **HARDCODED** | `R3d1sS3cr3tP@ssw0rd!` |
| `MYSQL_HOST` | 🟡 Hostname | `mysql-prod.internal.mycompany.com` |
| `MYSQL_USERNAME` | 🟡 Username | `mysql_admin` |
| `MYSQL_PASSWORD` | 🚨 **HARDCODED** | `MySQLSup3rS3cr3t!2024` |
| `RABBITMQ_URI` | 🚨 **HARDCODED** (full URI with credentials) | `amqps://rmq_user:RabbitmqS3cr3t!P%40ss@rabbitmq-prod...` |
| `RABBITMQ_USERNAME` | 🟡 Username | `rmq_user` |
| `RABBITMQ_PASSWORD` | 🚨 **HARDCODED** | `RabbitmqS3cr3t!P@ss` |
| `ELASTICSEARCH_USERNAME` | 🟡 Username | `elastic` |
| `ELASTICSEARCH_PASSWORD` | 🚨 **HARDCODED** | `3l@st1cS3cr3tP@ss!` |
| `ELASTICSEARCH_API_KEY` | 🚨 **HARDCODED** | `ZXMtYXBpLWtleS1pZDplcy1hcGkta2V5LXZhbHVlLXN0cmluZw==` |
| `MSSQL_CONNECTION_STRING` | 🚨 **HARDCODED** (full string with password) | `Server=mssql-prod...Password=MssqlSup3rS3cr3t!2024;...` |
| `MSSQL_USERNAME` | 🟡 Username | `sa` |
| `MSSQL_PASSWORD` | 🚨 **HARDCODED** | `MssqlSup3rS3cr3t!2024` |

### `js/auth.js`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `JWT_SECRET_KEY` | ✅ Safe | via `process.env` |
| `AUTH_KEY` | 🚨 **HARDCODED** | `aK3y!9Zq#rT2mXpL7@vN8$uB6wQs0cDeFgH` |
| `API_KEY` | 🚨 **HARDCODED** | `xK9#pL2@vN8mY$uP3rS3cr3tK3y!2024xZ` |
| `ACCESS_TOKEN` | ✅ Safe | via `process.env` |
| `REFRESH_TOKEN` | ✅ Safe | via `process.env` |
| `SESSION_SECRET` | ✅ Safe | via `process.env` |

### `js/cloud.js`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | ✅ Safe | via `process.env` |
| `AWS_SECRET_ACCESS_KEY` | ✅ Safe | via `process.env` |
| `AWS_ACCOUNT_ID` | ✅ Safe | via `process.env` |
| `ARTIFACTORY_USERNAME` | 🟡 Username | `deploy-bot` |
| `ARTIFACTORY_SECRET` | 🚨 **HARDCODED** | `AKCp8mBkLr9nT3vXqY2wZ5aF7hD0eG4iJ6oN1pR8sU` |
| `ARTIFACTORY_API_KEY` | ✅ Safe | via `process.env` |
| `GCP_CLIENT_EMAIL` | 🟡 Service account email | `service-account@my-production-project.iam.gserviceaccount.com` |
| `GCP_PROJECT_ID` | ✅ Safe | via `process.env` |
| `GCP_PRIVATE_KEY` | ✅ Safe | via `process.env` |
| `AZURE_TENANT_ID` | ✅ Safe | via `process.env` |
| `AZURE_CLIENT_ID` | ✅ Safe | via `process.env` |
| `AZURE_CLIENT_SECRET` | ✅ Safe | via `process.env` |
| `AZURE_STORAGE_ACCOUNT` | 🟡 Account name | `myproductionstorageacct` |
| `AZURE_STORAGE_KEY` | 🚨 **HARDCODED** | `dGhpcyBpcyBhIGZha2UgYXp1cmUgc3RvcmFnZSBhY2NvdW50IGtleSBmb3IgdGVzdGluZyBvbmx5==` |
| `VAULT_TOKEN` | ✅ Safe | via `process.env` |

### `js/db.config.js`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `DB_HOST` | ✅ Safe | via `process.env` |
| `DB_USERNAME` | ✅ Safe | via `process.env` |
| `DB_PASSWORD` | ✅ Safe | via `process.env` |
| `DB_REPLICA_HOST` | 🟡 Hostname | `replica-db.internal.mycompany.com` |
| `DB_REPLICA_USERNAME` | 🟡 Username | `replica_user` |
| `DB_REPLICA_PASSWORD` | 🚨 **HARDCODED** | `R3pl1caSup3rS3cr3t!2024#` |

### `js/payment.js`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `STRIPE_SECRET_KEY` | ✅ Safe | via `process.env` |
| `STRIPE_PUBLISHABLE_KEY` | ✅ Safe | via `process.env` |
| `STRIPE_WEBHOOK_SECRET` | ✅ Safe | via `process.env` |
| `PAYPAL_CLIENT_ID` | 🚨 **HARDCODED** | `AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUu12345` |
| `PAYPAL_CLIENT_SECRET` | ✅ Safe | via `process.env` |
| `BRAINTREE_MERCHANT_ID` | 🟡 Merchant ID | `merchant_abc123def456ghi` |
| `BRAINTREE_PUBLIC_KEY` | 🟡 Public key | `pub_jkl789mno012pqr345` |
| `BRAINTREE_PRIVATE_KEY` | ✅ Safe | via `process.env` |

### `js/integrations.js`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `GITHUB_TOKEN` | ✅ Safe | via `process.env` |
| `SLACK_WEBHOOK_URL` | ✅ Safe | via `process.env` |
| `SLACK_BOT_TOKEN` | ✅ Safe | via `process.env` |
| `TWILIO_ACCOUNT_SID` | ✅ Safe | via `process.env` |
| `TWILIO_AUTH_TOKEN` | ✅ Safe | via `process.env` |
| `SENDGRID_API_KEY` | 🚨 **HARDCODED** | `SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ.1234567890aBcDeFgHiJkLmNoPqRsTuVwXyZ` |
| `PAGERDUTY_INTEGRATION_KEY` | 🚨 **HARDCODED** | `c3a4b5d6e7f8a9b0c1d2e3f4a5b6c7d8` |
| `PAGERDUTY_API_TOKEN` | ✅ Safe | via `process.env` |

---

## 🐘 PHP Repo (`php/`)

### `php/auth.php`

> ⚠️ **Worst offender** — every secret is `define()`'d directly in source. No `.env` loading implemented.

| Variable | Status | Hardcoded Value |
|---|---|---|
| `JWT_SECRET_KEY` | 🚨 **HARDCODED** | `mY$uP3r$3cR3tJwTk3Y!xK9#pL2@vN8&qR5` |
| `AUTH_KEY` | 🚨 **HARDCODED** | `aK3y!9Zq#rT2mXpL7@vN8$uB6wQs0cDeFgH` |
| `API_KEY` | 🚨 **HARDCODED** | `xK9#pL2@vN8mY$uP3rS3cr3tK3y!2024xZ` |
| `ACCESS_TOKEN` | 🚨 **HARDCODED** | `tok_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890` |
| `REFRESH_TOKEN` | 🚨 **HARDCODED** | `rtok_live_ZyXwVuTsRqPoNmLkJiHgFeDcBa0987654321` |
| `SESSION_SECRET` | 🚨 **HARDCODED** | `s3ss10nS3cr3t!K3y#2024$XpZqR@vN8mYuP` |
| `OAUTH2_CLIENT_ID` | 🟡 Client ID | `myapp-client-id-aBcDeFgHiJkLmNoPqRs` |
| `OAUTH2_CLIENT_SECRET` | 🚨 **HARDCODED** | `oAuth2S3cr3t!K3y#2024$XpZqR@vN8mYuP3r` |

### `php/db.config.php`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `DB_HOST` | 🟡 Hostname | `prod-db.internal.mycompany.com` |
| `DB_USERNAME` | 🟡 Username | `admin_user` |
| `DB_PASSWORD` | 🚨 **HARDCODED** | `Sup3rS3cr3t!Passw0rd#2024` |
| `DB_REPLICA_HOST` | 🟡 Hostname | `replica-db.internal.mycompany.com` |
| `DB_REPLICA_USERNAME` | 🟡 Username | `replica_user` |
| `DB_REPLICA_PASSWORD` | 🚨 **HARDCODED** | `R3pl1caSup3rS3cr3t!2024#` |

### `php/connections.php`

> ⚠️ **Worst offender** — all URIs with embedded credentials and all passwords are `define()`'d directly in source.

| Variable | Status | Hardcoded Value |
|---|---|---|
| `MONGODB_URI` | 🚨 **HARDCODED** (full URI) | `mongodb+srv://app_admin:M0ng0S3cr3t!Passw0rd@cluster0...` |
| `MONGODB_PASSWORD` | 🚨 **HARDCODED** | `M0ng0S3cr3t!Passw0rd` |
| `REDIS_URI` | 🚨 **HARDCODED** (full URI) | `redis://:R3d1sS3cr3tP@ssw0rd!@redis-prod...` |
| `REDIS_PASSWORD` | 🚨 **HARDCODED** | `R3d1sS3cr3tP@ssw0rd!` |
| `MYSQL_URI` | 🚨 **HARDCODED** (full URI) | `mysql://mysql_admin:MySQLSup3rS3cr3t!2024@mysql-prod...` |
| `MYSQL_USERNAME` | 🟡 Username | `mysql_admin` |
| `MYSQL_PASSWORD` | 🚨 **HARDCODED** | `MySQLSup3rS3cr3t!2024` |
| `RABBITMQ_URI` | 🚨 **HARDCODED** (full URI) | `amqps://rmq_user:RabbitmqS3cr3t!P%40ss@rabbitmq-prod...` |
| `RABBITMQ_PASSWORD` | 🚨 **HARDCODED** | `RabbitmqS3cr3t!P@ss` |
| `ELASTICSEARCH_URI` | 🚨 **HARDCODED** (full URI) | `https://elastic:3l%40st1cS3cr3tP%40ss!@elasticsearch-prod...` |
| `ELASTICSEARCH_PASSWORD` | 🚨 **HARDCODED** | `3l@st1cS3cr3tP@ss!` |
| `ELASTICSEARCH_API_KEY` | 🚨 **HARDCODED** | `ZXMtYXBpLWtleS1pZDplcy1hcGkta2V5LXZhbHVlLXN0cmluZw==` |
| `MSSQL_CONNECTION_STRING` | 🚨 **HARDCODED** (full string) | `Server=mssql-prod...Password=MssqlSup3rS3cr3t!2024;...` |
| `MSSQL_USERNAME` | 🟡 Username | `sa` |
| `MSSQL_PASSWORD` | 🚨 **HARDCODED** | `MssqlSup3rS3cr3t!2024` |

### `php/cloud.php`

> ⚠️ **Worst offender** — AWS keys, Artifactory secrets, Azure credentials, and Vault Token all hardcoded via `define()`.

| Variable | Status | Hardcoded Value |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | 🚨 **HARDCODED** | `AKIAIOSFODNN7EXAMPLE` |
| `AWS_SECRET_ACCESS_KEY` | 🚨 **HARDCODED** | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| `AWS_ACCOUNT_ID` | 🟡 Account ID | `123456789012` |
| `ARTIFACTORY_USERNAME` | 🟡 Username | `deploy-bot` |
| `ARTIFACTORY_SECRET` | 🚨 **HARDCODED** | `AKCp8mBkLr9nT3vXqY2wZ5aF7hD0eG4iJ6oN1pR8sU` |
| `ARTIFACTORY_API_KEY` | 🚨 **HARDCODED** | `AKCp8jHnWx3vZqR7mT9pL2yF5dG0eN4oK1aB6cD8iJ` |
| `GCP_PROJECT_ID` | 🟡 Project ID | `my-production-project` |
| `GCP_CLIENT_EMAIL` | 🟡 Service account email | `service-account@my-production-project.iam.gserviceaccount.com` |
| `GCP_PRIVATE_KEY` | ✅ Safe | via `getenv()` *(⚠️ but env key name is garbled — fix it)* |
| `AZURE_TENANT_ID` | 🚨 **HARDCODED** | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| `AZURE_CLIENT_ID` | 🚨 **HARDCODED** | `b2c3d4e5-f6a7-8901-bcde-f01234567891` |
| `AZURE_CLIENT_SECRET` | 🚨 **HARDCODED** | `aB3~cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5` |
| `AZURE_STORAGE_ACCOUNT` | 🟡 Account name | `myproductionstorageacct` |
| `AZURE_STORAGE_KEY` | 🚨 **HARDCODED** | `dGhpcyBpcyBhIGZha2UgYXp1cmUgc3RvcmFnZSBhY2NvdW50IGtleSBmb3IgdGVzdGluZyBvbmx5==` |
| `VAULT_TOKEN` | 🚨 **HARDCODED** | `s.aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890` |

### `php/payment.php`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `STRIPE_SECRET_KEY` | ✅ Safe | via `getenv()` |
| `STRIPE_PUBLISHABLE_KEY` | ✅ Safe | via `getenv()` |
| `STRIPE_WEBHOOK_SECRET` | ✅ Safe | via `getenv()` |
| `PAYPAL_CLIENT_ID` | 🚨 **HARDCODED** | `AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUu12345` |
| `PAYPAL_CLIENT_SECRET` | 🚨 **HARDCODED** | `EGk2tXv9pL8mNqR3sY7wZ0aB5cD4eF6gH1iJ2kL3mN4oP5` |
| `BRAINTREE_MERCHANT_ID` | 🟡 Merchant ID | `merchant_abc123def456ghi` |
| `BRAINTREE_PUBLIC_KEY` | 🟡 Public key | `pub_jkl789mno012pqr345` |
| `BRAINTREE_PRIVATE_KEY` | 🚨 **HARDCODED** | `prv_stu678vwx901yza234bcd567efg890hij` |

### `php/integrations.php`

| Variable | Status | Hardcoded Value |
|---|---|---|
| `GITHUB_TOKEN` | ✅ Safe | via `getenv()` |
| `SLACK_WEBHOOK_URL` | ✅ Safe | via `getenv('HTTPS')` *(⚠️ misleading key name — rename to `SLACK_WEBHOOK_URL`)* |
| `SLACK_BOT_TOKEN` | ✅ Safe | via `getenv('SLACK_TOKEN')` *(⚠️ inconsistent key name — rename to `SLACK_BOT_TOKEN`)* |
| `TWILIO_ACCOUNT_SID` | ✅ Safe | via `getenv()` |
| `TWILIO_AUTH_TOKEN` | 🚨 **HARDCODED** | `3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c` |
| `SENDGRID_API_KEY` | 🚨 **HARDCODED** | `SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ.1234567890aBcDeFgHiJkLmNoPqRsTuVwXyZ` |
| `PAGERDUTY_INTEGRATION_KEY` | 🚨 **HARDCODED** | `c3a4b5d6e7f8a9b0c1d2e3f4a5b6c7d8` |
| `PAGERDUTY_API_TOKEN` | 🚨 **HARDCODED** | `u+xYz_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234` |

---

## 🏆 Worst Offenders (Ranked by file)

| Rank | File | Issues |
|---|---|---|
| 🥇 1 | `php/connections.php` | All URIs + passwords hardcoded as PHP `define()` — no env loading |
| 🥈 2 | `php/auth.php` | All 8 auth secrets hardcoded as PHP `define()` — no env loading |
| 🥉 3 | `php/cloud.php` | AWS, Artifactory, Azure, Vault Token all hardcoded |
| 4 | `python/connections.py` | Redis, MySQL, RabbitMQ, Elasticsearch, MSSQL passwords raw in code |
| 5 | `js/connections.js` | Redis, MySQL, RabbitMQ, Elasticsearch, MSSQL passwords raw in code |

---

## ✅ Remediation Recommendations

1. **Move all 🚨 secrets to `.env` files** and read them via environment variables only.
2. **Never commit `.env` files** — add all `.env*` patterns to `.gitignore` immediately.
3. **Fix misleading env key names** in `php/integrations.php` and `php/cloud.php`:
   - `HTTPS` → `SLACK_WEBHOOK_URL`
   - `SLACK_TOKEN` → `SLACK_BOT_TOKEN`
   - `NA_BC_DE_FG_HI_JK_LM_NO_PQ_RS_TU_VW_XY_Z1234...` → `GCP_PRIVATE_KEY`
4. **Implement `phpdotenv`** (`vlucas/phpdotenv`) in all PHP files — TODOs already exist in some files but are not yet activated.
5. **Rotate all exposed secrets immediately** — treat every 🚨 hardcoded value as compromised.
6. **Consider a secrets manager** (e.g., HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) for production credentials instead of flat `.env` files.
7. **Add a pre-commit hook** using a tool like `gitleaks`, `trufflehog`, or `git-secrets` to prevent secrets from being committed in the future.


