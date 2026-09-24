import { Rule } from '../../types';

/**
 * Third-party cloud / SaaS service credential patterns.
 * Covers: GitHub, Stripe, Twilio, SendGrid, Slack, Heroku,
 *         Mailgun, Cloudflare, Datadog, NPM, Docker Hub,
 *         OpenAI, Anthropic, Telegram, Discord, Supabase,
 *         Vercel, DigitalOcean, Algolia, Mapbox, Pinecone,
 *         Vault, Airtable, HubSpot, Square, Razorpay, Plaid, etc.
 */
export const cloudRules: Rule[] = [
  // ── GitHub ──────────────────────────────────────────────────────────────────
  {
    id: 'github-personal-access-token',
    description: 'GitHub Personal Access Token (classic ghp_)',
    pattern: /['"\`](ghp_[A-Za-z0-9]{36,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'GITHUB_TOKEN',
    severity: 'critical',
  },
  {
    id: 'github-oauth-token',
    description: 'GitHub OAuth Token (gho_)',
    pattern: /['"\`](gho_[A-Za-z0-9]{36,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'GITHUB_OAUTH_TOKEN',
    severity: 'critical',
  },
  {
    id: 'github-app-token',
    description: 'GitHub App Installation Token (ghs_ / ghu_)',
    pattern: /['"\`](gh[su]_[A-Za-z0-9]{36,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'GITHUB_APP_TOKEN',
    severity: 'critical',
  },
  {
    id: 'github-fine-grained-token',
    description: 'GitHub Fine-Grained Personal Access Token (github_pat_)',
    pattern: /['"\`](github_pat_[A-Za-z0-9_]{82,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'GITHUB_PAT',
    severity: 'critical',
  },
  // ── GitLab ───────────────────────────────────────────────────────────────────
  {
    id: 'gitlab-personal-access-token',
    description: 'GitLab Personal Access Token (glpat-)',
    pattern: /['"\`](glpat-[A-Za-z0-9\-_]{20,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'GITLAB_TOKEN',
    severity: 'critical',
  },
  {
    id: 'gitlab-runner-token',
    description: 'GitLab Runner Registration Token',
    pattern: /(?:gitlab[_-]?runner[_-]?token|GITLAB_RUNNER_TOKEN|CI_REGISTRATION_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GITLAB_RUNNER_TOKEN',
    severity: 'critical',
  },
  // ── Stripe ───────────────────────────────────────────────────────────────────
  {
    id: 'stripe-secret-key',
    description: 'Stripe Secret Key (sk_live_ or sk_test_)',
    pattern: /['"\`](sk_(?:live|test)_[A-Za-z0-9]{24,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'STRIPE_SECRET_KEY',
    severity: 'critical',
  },
  {
    id: 'stripe-publishable-key',
    description: 'Stripe Publishable Key (pk_live_ or pk_test_)',
    pattern: /['"\`](pk_(?:live|test)_[A-Za-z0-9]{24,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'STRIPE_PUBLISHABLE_KEY',
    severity: 'high',
  },
  {
    id: 'stripe-webhook-secret',
    description: 'Stripe Webhook Signing Secret (whsec_)',
    pattern: /['"\`](whsec_[A-Za-z0-9]{32,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'STRIPE_WEBHOOK_SECRET',
    severity: 'critical',
  },
  {
    id: 'stripe-restricted-key',
    description: 'Stripe Restricted Key (rk_live_ or rk_test_)',
    pattern: /['"\`](rk_(?:live|test)_[A-Za-z0-9]{24,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'STRIPE_RESTRICTED_KEY',
    severity: 'critical',
  },
  // ── Twilio ───────────────────────────────────────────────────────────────────
  {
    id: 'twilio-account-sid',
    description: 'Twilio Account SID',
    pattern: /['"\`](AC[a-f0-9]{32})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'TWILIO_ACCOUNT_SID',
    severity: 'high',
  },
  {
    id: 'twilio-auth-token',
    description: 'Twilio Auth Token',
    pattern: /(?:twilio[_-]?auth[_-]?token|TWILIO_AUTH_TOKEN)\s*[:=]\s*['"\`]([a-f0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'TWILIO_AUTH_TOKEN',
    severity: 'critical',
  },
  {
    id: 'twilio-api-key',
    description: 'Twilio API Key SID (SK prefix)',
    pattern: /['"\`](SK[a-f0-9]{32})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'TWILIO_API_KEY',
    severity: 'critical',
  },
  // ── SendGrid ─────────────────────────────────────────────────────────────────
  {
    id: 'sendgrid-api-key',
    description: 'SendGrid API Key',
    pattern: /['"\`](SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'SENDGRID_API_KEY',
    severity: 'critical',
  },
  // ── Slack ─────────────────────────────────────────────────────────────────────
  {
    id: 'slack-bot-token',
    description: 'Slack Bot / User Token (xoxb- / xoxp-)',
    pattern: /['"\`](xox[bpoa]-[A-Za-z0-9\-]{10,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'SLACK_TOKEN',
    severity: 'critical',
  },
  {
    id: 'slack-webhook-url',
    description: 'Slack Incoming Webhook URL',
    pattern: /['"\`](https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'SLACK_WEBHOOK_URL',
    severity: 'high',
  },
  {
    id: 'slack-signing-secret',
    description: 'Slack Signing Secret',
    pattern: /(?:slack[_-]?signing[_-]?secret|SLACK_SIGNING_SECRET)\s*[:=]\s*['"\`]([a-f0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SLACK_SIGNING_SECRET',
    severity: 'critical',
  },
  // ── Mailgun ───────────────────────────────────────────────────────────────────
  {
    id: 'mailgun-api-key',
    description: 'Mailgun API Key',
    pattern: /['"\`](key-[A-Za-z0-9]{32})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'MAILGUN_API_KEY',
    severity: 'critical',
  },
  // ── Cloudflare ────────────────────────────────────────────────────────────────
  {
    id: 'cloudflare-api-token',
    description: 'Cloudflare API Token',
    pattern: /(?:cloudflare[_-]?api[_-]?token|CF_API_TOKEN|CLOUDFLARE_API_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{40})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CLOUDFLARE_API_TOKEN',
    severity: 'critical',
  },
  {
    id: 'cloudflare-global-api-key',
    description: 'Cloudflare Global API Key',
    pattern: /(?:cloudflare[_-]?(?:global[_-]?)?(?:api[_-]?)?key|CF_API_KEY|CLOUDFLARE_API_KEY)\s*[:=]\s*['"\`]([a-f0-9]{37})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CLOUDFLARE_API_KEY',
    severity: 'critical',
  },
  // ── Datadog ───────────────────────────────────────────────────────────────────
  {
    id: 'datadog-api-key',
    description: 'Datadog API Key',
    pattern: /(?:dd[_-]?api[_-]?key|datadog[_-]?api[_-]?key|DD_API_KEY)\s*[:=]\s*['"\`]([a-f0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DD_API_KEY',
    severity: 'critical',
  },
  {
    id: 'datadog-app-key',
    description: 'Datadog Application Key',
    pattern: /(?:dd[_-]?app[_-]?key|datadog[_-]?app[_-]?key|DD_APP_KEY)\s*[:=]\s*['"\`]([a-f0-9]{40})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DD_APP_KEY',
    severity: 'critical',
  },
  // ── NPM ───────────────────────────────────────────────────────────────────────
  {
    id: 'npm-auth-token',
    description: 'NPM Auth Token',
    pattern: /(?:npm[_-]?(?:auth[_-]?)?token|NPM_TOKEN|NODE_AUTH_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9\-]{36,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'NPM_TOKEN',
    severity: 'critical',
  },
  // ── Heroku ────────────────────────────────────────────────────────────────────
  {
    id: 'heroku-api-key',
    description: 'Heroku API Key (UUID)',
    pattern: /(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[:=]\s*['"\`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'HEROKU_API_KEY',
    severity: 'critical',
  },
  // ── Shopify ───────────────────────────────────────────────────────────────────
  {
    id: 'shopify-access-token',
    description: 'Shopify Private App Access Token (shpat_)',
    pattern: /(?:shopify[_-]?(?:access[_-]?)?token|SHOPIFY_ACCESS_TOKEN)\s*[:=]\s*['"\`](shpat_[A-Za-z0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SHOPIFY_ACCESS_TOKEN',
    severity: 'critical',
  },
  {
    id: 'shopify-shared-secret',
    description: 'Shopify App Shared Secret',
    pattern: /(?:shopify[_-]?(?:shared[_-]?|api[_-]?)?secret|SHOPIFY_API_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SHOPIFY_SECRET',
    severity: 'critical',
  },
  // ── Firebase ─────────────────────────────────────────────────────────────────
  {
    id: 'firebase-server-key',
    description: 'Firebase Cloud Messaging Server Key',
    pattern: /(?:firebase[_-]?server[_-]?key|FCM_SERVER_KEY)\s*[:=]\s*['"\`](AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'FCM_SERVER_KEY',
    severity: 'critical',
  },
  // ── Auth0 ─────────────────────────────────────────────────────────────────────
  {
    id: 'auth0-client-secret',
    description: 'Auth0 Client Secret',
    pattern: /(?:auth0[_-]?client[_-]?secret|AUTH0_CLIENT_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{43})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AUTH0_CLIENT_SECRET',
    severity: 'critical',
  },
  // ── Sentry ────────────────────────────────────────────────────────────────────
  {
    id: 'sentry-dsn',
    description: 'Sentry DSN (contains secret)',
    pattern: /(?:sentry[_-]?dsn|SENTRY_DSN)\s*[:=]\s*['"\`](https?:\/\/[a-f0-9]+@[^'"\`\s]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SENTRY_DSN',
    severity: 'high',
  },
  // ── Mailchimp ─────────────────────────────────────────────────────────────────
  {
    id: 'mailchimp-api-key',
    description: 'Mailchimp API Key',
    pattern: /['"\`]([A-Za-z0-9]{32}-us\d{1,2})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'MAILCHIMP_API_KEY',
    severity: 'critical',
  },
  // ── PayPal ────────────────────────────────────────────────────────────────────
  {
    id: 'paypal-client-secret',
    description: 'PayPal Client Secret',
    pattern: /(?:paypal[_-]?client[_-]?secret|PAYPAL_CLIENT_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{64,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PAYPAL_CLIENT_SECRET',
    severity: 'critical',
  },
  // ── Pusher ────────────────────────────────────────────────────────────────────
  {
    id: 'pusher-app-secret',
    description: 'Pusher App Secret',
    pattern: /(?:pusher[_-]?(?:app[_-]?)?secret|PUSHER_APP_SECRET)\s*[:=]\s*['"\`]([a-f0-9]{20})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PUSHER_APP_SECRET',
    severity: 'critical',
  },
  // ── Okta ─────────────────────────────────────────────────────────────────────
  {
    id: 'okta-api-token',
    description: 'Okta API Token',
    pattern: /(?:okta[_-]?(?:api[_-]?)?token|OKTA_API_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{42})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'OKTA_API_TOKEN',
    severity: 'critical',
  },
  // ── OpenAI ───────────────────────────────────────────────────────────────────
  {
    id: 'openai-api-key',
    description: 'OpenAI API Key (sk-...)',
    pattern: /['"\`](sk-[A-Za-z0-9]{48,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'OPENAI_API_KEY',
    severity: 'critical',
  },
  {
    id: 'openai-org-id',
    description: 'OpenAI Organization ID',
    pattern: /(?:openai[_-]?org(?:anization)?[_-]?id|OPENAI_ORG_ID)\s*[:=]\s*['"\`](org-[A-Za-z0-9]{24,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'OPENAI_ORG_ID',
    severity: 'high',
  },
  // ── Anthropic ────────────────────────────────────────────────────────────────
  {
    id: 'anthropic-api-key',
    description: 'Anthropic Claude API Key (sk-ant-...)',
    pattern: /['"\`](sk-ant-[A-Za-z0-9\-_]{93,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'ANTHROPIC_API_KEY',
    severity: 'critical',
  },
  // ── Hugging Face ─────────────────────────────────────────────────────────────
  {
    id: 'huggingface-token',
    description: 'Hugging Face User Access Token (hf_)',
    pattern: /['"\`](hf_[A-Za-z0-9]{34,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'HUGGINGFACE_TOKEN',
    severity: 'critical',
  },
  // ── Pinecone ─────────────────────────────────────────────────────────────────
  {
    id: 'pinecone-api-key',
    description: 'Pinecone API Key',
    pattern: /(?:pinecone[_-]?api[_-]?key|PINECONE_API_KEY)\s*[:=]\s*['"\`]([a-f0-9\-]{36,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PINECONE_API_KEY',
    severity: 'critical',
  },
  // ── Supabase ─────────────────────────────────────────────────────────────────
  {
    id: 'supabase-service-role-key',
    description: 'Supabase Service Role Key (JWT)',
    pattern: /(?:supabase[_-]?service[_-]?(?:role[_-]?)?key|SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SUPABASE_SERVICE_ROLE_KEY',
    severity: 'critical',
  },
  {
    id: 'supabase-anon-key',
    description: 'Supabase Anon / Public Key (JWT)',
    pattern: /(?:supabase[_-]?anon[_-]?key|supabase[_-]?public[_-]?key|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SUPABASE_ANON_KEY',
    severity: 'high',
  },
  // ── Vercel ───────────────────────────────────────────────────────────────────
  {
    id: 'vercel-token',
    description: 'Vercel Personal Access Token',
    pattern: /(?:vercel[_-]?(?:api[_-]?)?token|VERCEL_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{24,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'VERCEL_TOKEN',
    severity: 'critical',
  },
  // ── DigitalOcean ─────────────────────────────────────────────────────────────
  {
    id: 'digitalocean-token',
    description: 'DigitalOcean Personal Access Token',
    pattern: /(?:digitalocean[_-]?(?:api[_-]?)?token|do[_-]?token|DIGITALOCEAN_TOKEN|DO_API_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{64,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DIGITALOCEAN_TOKEN',
    severity: 'critical',
  },
  {
    id: 'digitalocean-spaces-key',
    description: 'DigitalOcean Spaces Access Key',
    pattern: /(?:spaces[_-]?(?:access[_-]?)?key|DO_SPACES_KEY|SPACES_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9]{20})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DO_SPACES_KEY',
    severity: 'critical',
  },
  // ── Algolia ───────────────────────────────────────────────────────────────────
  {
    id: 'algolia-admin-api-key',
    description: 'Algolia Admin API Key',
    pattern: /(?:algolia[_-]?admin[_-]?(?:api[_-]?)?key|ALGOLIA_ADMIN_API_KEY|ALGOLIA_API_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ALGOLIA_ADMIN_API_KEY',
    severity: 'critical',
  },
  {
    id: 'algolia-app-id',
    description: 'Algolia Application ID',
    pattern: /(?:algolia[_-]?app(?:lication)?[_-]?id|ALGOLIA_APP_ID)\s*[:=]\s*['"\`]([A-Z0-9]{10})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ALGOLIA_APP_ID',
    severity: 'medium',
  },
  // ── Mapbox ───────────────────────────────────────────────────────────────────
  {
    id: 'mapbox-access-token',
    description: 'Mapbox Access Token (pk.eyJ... or sk.eyJ...)',
    pattern: /['"\`]([ps]k\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.]+)['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'MAPBOX_ACCESS_TOKEN',
    severity: 'critical',
  },
  // ── Telegram ─────────────────────────────────────────────────────────────────
  {
    id: 'telegram-bot-token',
    description: 'Telegram Bot API Token',
    pattern: /(?:telegram[_-]?(?:bot[_-]?)?token|TELEGRAM_BOT_TOKEN|BOT_TOKEN)\s*[:=]\s*['"\`](\d{8,10}:[A-Za-z0-9\-_]{35})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'TELEGRAM_BOT_TOKEN',
    severity: 'critical',
  },
  // ── Discord ───────────────────────────────────────────────────────────────────
  {
    id: 'discord-bot-token',
    description: 'Discord Bot Token',
    pattern: /(?:discord[_-]?(?:bot[_-]?)?token|DISCORD_TOKEN|DISCORD_BOT_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{24}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DISCORD_BOT_TOKEN',
    severity: 'critical',
  },
  {
    id: 'discord-webhook-url',
    description: 'Discord Incoming Webhook URL',
    pattern: /['"\`](https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9\-_]+)['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'DISCORD_WEBHOOK_URL',
    severity: 'high',
  },
  {
    id: 'discord-client-secret',
    description: 'Discord OAuth2 Client Secret',
    pattern: /(?:discord[_-]?client[_-]?secret|DISCORD_CLIENT_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{32,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DISCORD_CLIENT_SECRET',
    severity: 'critical',
  },
  // ── Notion ────────────────────────────────────────────────────────────────────
  {
    id: 'notion-integration-token',
    description: 'Notion Internal Integration Token (secret_...)',
    pattern: /['"\`](secret_[A-Za-z0-9]{43,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'NOTION_TOKEN',
    severity: 'critical',
  },
  // ── Linear ───────────────────────────────────────────────────────────────────
  {
    id: 'linear-api-key',
    description: 'Linear API Key (lin_api_...)',
    pattern: /['"\`](lin_api_[A-Za-z0-9]{40,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'LINEAR_API_KEY',
    severity: 'critical',
  },
  // ── Airtable ─────────────────────────────────────────────────────────────────
  {
    id: 'airtable-api-key',
    description: 'Airtable API Key or Personal Access Token',
    pattern: /(?:airtable[_-]?(?:api[_-]?)?key|airtable[_-]?(?:pat|token)|AIRTABLE_API_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9.]{14,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AIRTABLE_API_KEY',
    severity: 'critical',
  },
  // ── HubSpot ───────────────────────────────────────────────────────────────────
  {
    id: 'hubspot-api-key',
    description: 'HubSpot API Key or Private App Token (pat-...)',
    pattern: /(?:hubspot[_-]?(?:api[_-]?)?(?:key|token)|HUBSPOT_API_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'HUBSPOT_API_KEY',
    severity: 'critical',
  },
  // ── Zendesk ───────────────────────────────────────────────────────────────────
  {
    id: 'zendesk-api-token',
    description: 'Zendesk API Token',
    pattern: /(?:zendesk[_-]?(?:api[_-]?)?token|ZENDESK_API_TOKEN|ZENDESK_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{40,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ZENDESK_API_TOKEN',
    severity: 'critical',
  },
  // ── Intercom ─────────────────────────────────────────────────────────────────
  {
    id: 'intercom-access-token',
    description: 'Intercom Access Token',
    pattern: /(?:intercom[_-]?(?:access[_-]?)?token|INTERCOM_TOKEN|INTERCOM_ACCESS_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9_\-]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'INTERCOM_TOKEN',
    severity: 'critical',
  },
  // ── Braintree ─────────────────────────────────────────────────────────────────
  {
    id: 'braintree-private-key',
    description: 'Braintree Private Key',
    pattern: /(?:braintree[_-]?private[_-]?key|BRAINTREE_PRIVATE_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'BRAINTREE_PRIVATE_KEY',
    severity: 'critical',
  },
  // ── Square ────────────────────────────────────────────────────────────────────
  {
    id: 'square-access-token',
    description: 'Square Access Token',
    pattern: /(?:square[_-]?(?:access[_-]?)?token|SQUARE_ACCESS_TOKEN)\s*[:=]\s*['"\`](EAA[A-Za-z0-9]{60,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SQUARE_ACCESS_TOKEN',
    severity: 'critical',
  },
  // ── Razorpay ─────────────────────────────────────────────────────────────────
  {
    id: 'razorpay-key-secret',
    description: 'Razorpay Key Secret',
    pattern: /(?:razorpay[_-]?(?:key[_-]?)?secret|RAZORPAY_KEY_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'RAZORPAY_KEY_SECRET',
    severity: 'critical',
  },
  // ── Plaid ─────────────────────────────────────────────────────────────────────
  {
    id: 'plaid-client-secret',
    description: 'Plaid Client Secret',
    pattern: /(?:plaid[_-]?client[_-]?secret|plaid[_-]?secret|PLAID_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9]{30,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PLAID_SECRET',
    severity: 'critical',
  },
  // ── Cloudinary ────────────────────────────────────────────────────────────────
  {
    id: 'cloudinary-api-secret',
    description: 'Cloudinary API Secret',
    pattern: /(?:cloudinary[_-]?api[_-]?secret|CLOUDINARY_API_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{27,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CLOUDINARY_API_SECRET',
    severity: 'critical',
  },
  {
    id: 'cloudinary-url',
    description: 'Cloudinary URL with embedded credentials',
    pattern: /(?:cloudinary[_-]?url|CLOUDINARY_URL)\s*[:=]\s*['"\`](cloudinary:\/\/[^'"\`\s]+:[^'"\`\s]+@[^'"\`\s]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CLOUDINARY_URL',
    severity: 'critical',
  },
  // ── Amplitude ────────────────────────────────────────────────────────────────
  {
    id: 'amplitude-api-key',
    description: 'Amplitude API Key or Secret Key',
    pattern: /(?:amplitude[_-]?(?:api[_-]?|secret[_-]?)?key|AMPLITUDE_API_KEY|AMPLITUDE_SECRET_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AMPLITUDE_API_KEY',
    severity: 'high',
  },
  // ── MixPanel ─────────────────────────────────────────────────────────────────
  {
    id: 'mixpanel-token',
    description: 'Mixpanel Project Token or API Secret',
    pattern: /(?:mixpanel[_-]?(?:(?:project[_-]?)?token|secret|api[_-]?secret)|MIXPANEL_TOKEN|MIXPANEL_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'MIXPANEL_TOKEN',
    severity: 'high',
  },
  // ── Segment ───────────────────────────────────────────────────────────────────
  {
    id: 'segment-write-key',
    description: 'Segment Write Key',
    pattern: /(?:segment[_-]?write[_-]?key|SEGMENT_WRITE_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9]{32,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SEGMENT_WRITE_KEY',
    severity: 'high',
  },
  // ── LaunchDarkly ─────────────────────────────────────────────────────────────
  {
    id: 'launchdarkly-sdk-key',
    description: 'LaunchDarkly SDK Key (sdk-...)',
    pattern: /['"\`](sdk-[A-Za-z0-9\-_]{40,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'LAUNCHDARKLY_SDK_KEY',
    severity: 'critical',
  },
  // ── Terraform Cloud ───────────────────────────────────────────────────────────
  {
    id: 'terraform-cloud-token',
    description: 'Terraform Cloud / HCP API Token',
    pattern: /(?:terraform[_-]?(?:cloud[_-]?)?token|TFC_TOKEN|TF_TOKEN|TERRAFORM_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9.]{14,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'TERRAFORM_CLOUD_TOKEN',
    severity: 'critical',
  },
  // ── HashiCorp Vault ───────────────────────────────────────────────────────────
  {
    id: 'vault-token',
    description: 'HashiCorp Vault Token (s. prefix or root token)',
    pattern: /(?:vault[_-]?token|VAULT_TOKEN)\s*[:=]\s*['"\`](s\.[A-Za-z0-9]{24,}|hvs\.[A-Za-z0-9]{90,}|root)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'VAULT_TOKEN',
    severity: 'critical',
  },
  // ── Confluent / Kafka ─────────────────────────────────────────────────────────
  {
    id: 'confluent-api-secret',
    description: 'Confluent Cloud API Secret',
    pattern: /(?:confluent[_-]?(?:api[_-]?)?secret|CONFLUENT_SECRET|CONFLUENT_API_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9+/=]{52,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CONFLUENT_API_SECRET',
    severity: 'critical',
  },
  // ── Docker Hub ───────────────────────────────────────────────────────────────
  {
    id: 'dockerhub-password',
    description: 'Docker Hub password or access token',
    pattern: /(?:docker(?:hub)?[_-]?(?:password|pass|token|pat)|DOCKER_PASSWORD|DOCKERHUB_TOKEN)\s*[:=]\s*['"\`]([^'"\`\n]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DOCKERHUB_TOKEN',
    severity: 'critical',
  },
  // ── Jira / Atlassian ─────────────────────────────────────────────────────────
  {
    id: 'jira-api-token',
    description: 'Jira / Atlassian API Token',
    pattern: /(?:jira[_-]?(?:api[_-]?)?token|atlassian[_-]?(?:api[_-]?)?token|JIRA_API_TOKEN|ATLASSIAN_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{24,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'JIRA_API_TOKEN',
    severity: 'critical',
  },
  // ── PagerDuty ────────────────────────────────────────────────────────────────
  {
    id: 'pagerduty-api-key',
    description: 'PagerDuty API Key',
    pattern: /(?:pagerduty[_-]?(?:api[_-]?)?(?:key|token)|PAGERDUTY_TOKEN|PAGERDUTY_API_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9+/\-_]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PAGERDUTY_API_KEY',
    severity: 'critical',
  },
  // ── Grafana ───────────────────────────────────────────────────────────────────
  {
    id: 'grafana-api-key',
    description: 'Grafana API Key or Service Account Token (glsa_)',
    pattern: /(?:grafana[_-]?(?:api[_-]?)?(?:key|token)|GRAFANA_API_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.=]{32,}|glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GRAFANA_API_KEY',
    severity: 'critical',
  },
  // ── New Relic ─────────────────────────────────────────────────────────────────
  {
    id: 'newrelic-api-key',
    description: 'New Relic API Key (NRAK- or NRAA-)',
    pattern: /['"\`]((?:NRAK|NRAA)-[A-Z0-9]{27})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'NEW_RELIC_API_KEY',
    severity: 'critical',
  },
  // ── Dynatrace ─────────────────────────────────────────────────────────────────
  {
    id: 'dynatrace-api-token',
    description: 'Dynatrace API Token (dt0c01. prefix)',
    pattern: /['"\`](dt0[a-zA-Z0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'DYNATRACE_API_TOKEN',
    severity: 'critical',
  },
  // ── Cohere ───────────────────────────────────────────────────────────────────
  {
    id: 'cohere-api-key',
    description: 'Cohere API Key',
    pattern: /(?:cohere[_-]?(?:api[_-]?)?key|COHERE_API_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9]{40,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'COHERE_API_KEY',
    severity: 'critical',
  },
  // ── Replicate ────────────────────────────────────────────────────────────────
  {
    id: 'replicate-api-token',
    description: 'Replicate API Token (r8_...)',
    pattern: /['"\`](r8_[A-Za-z0-9]{40,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'REPLICATE_API_TOKEN',
    severity: 'critical',
  },

  // ── PayPal ────────────────────────────────────────────────────────────────────
  {
    id: 'paypal-client-id',
    description: 'PayPal Client ID (hardcoded)',
    pattern: /(?:define\s*\(\s*[''"](PAYPAL_CLIENT_ID)[''"\`]\s*,\s*|(?:paypal[_-]?client[_-]?id|PAYPAL_CLIENT_ID)\s*[:=]\s*)[''"\`]([A-Za-z0-9\-_]{20,})[''"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PAYPAL_CLIENT_ID',
    severity: 'high',
  },
  // ── PagerDuty Integration Key ─────────────────────────────────────────────────
  {
    id: 'pagerduty-integration-key',
    description: 'PagerDuty Events API / Integration Key (32 hex chars)',
    pattern: /(?:pagerduty[_-]?(?:integration[_-]?|events?[_-]?)?key|PAGERDUTY_INTEGRATION_KEY|PAGERDUTY_EVENTS_KEY)\s*[:=,]\s*[''"\`]([a-f0-9]{32})[''"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PAGERDUTY_INTEGRATION_KEY',
    severity: 'critical',
  },
  // ── JFrog Artifactory ─────────────────────────────────────────────────────────
  {
    id: 'artifactory-secret',
    description: 'JFrog Artifactory Identity Token or Secret',
    pattern: /(?:artifactory[_-]?(?:secret|identity[_-]?token)|ARTIFACTORY_SECRET)\s*[:=,]\s*[''"\`]([A-Za-z0-9]{20,})[''"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ARTIFACTORY_SECRET',
    severity: 'critical',
  },
  {
    id: 'artifactory-api-key',
    description: 'JFrog Artifactory API Key',
    pattern: /(?:artifactory[_-]?api[_-]?key|ARTIFACTORY_API_KEY)\s*[:=,]\s*[''"\`]([A-Za-z0-9]{20,})[''"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ARTIFACTORY_API_KEY',
    severity: 'critical',
  },
  {
    id: 'artifactory-akc-token-bare',
    description: 'JFrog Artifactory AKC-prefixed token (bare)',
    pattern: /[''"\`](AKC[A-Za-z0-9]{20,})[''"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'ARTIFACTORY_TOKEN',
    severity: 'critical',
  },
  // ── AWS Secret Access Key bare ────────────────────────────────────────────────
  {
    id: 'aws-secret-access-key-bare',
    description: 'AWS Secret Access Key (bare, named variable without full aws_ prefix)',
    pattern: /(?:aws[_-]?secret|SECRET_ACCESS_KEY|secret_access_key)\s*[:=,]\s*[''"\`]([A-Za-z0-9+\/]{40})[''"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_SECRET_ACCESS_KEY',
    severity: 'critical',
  },

  // ── Bitbucket ─────────────────────────────────────────────────────────────────
  {
    id: 'bitbucket-app-password',
    description: 'Bitbucket App Password used for REST API authentication',
    pattern: /(?:bitbucket[_-]?(?:app[_-]?)?password|BITBUCKET_APP_PASSWORD)\s*[:=]\s*['"`]([A-Za-z0-9+/]{20,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'BITBUCKET_APP_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'bitbucket-client-secret',
    description: 'Bitbucket OAuth Consumer Secret',
    pattern: /(?:bitbucket[_-]?(?:client[_-]?|oauth[_-]?)?secret|BITBUCKET_CLIENT_SECRET)\s*[:=]\s*['"`]([A-Za-z0-9+/]{20,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'BITBUCKET_CLIENT_SECRET',
    severity: 'critical',
  },

  // DigitalOcean PAT
  {
    id: 'digitalocean-personal-access-token',
    description: 'DigitalOcean Personal Access Token (dop_v1_ prefix)',
    pattern: /['"\`](dop_v1_[A-Za-z0-9]{64,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'DO_TOKEN',
    severity: 'critical',
  },
  // DigitalOcean Spaces Secret
  {
    id: 'digitalocean-spaces-secret',
    description: 'DigitalOcean Spaces Secret Access Key',
    pattern: /(?:do[_-]?spaces[_-]?secret|DO_SPACES_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9\/+]{40})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DO_SPACES_SECRET',
    severity: 'critical',
  },
  // Linear API Key
  {
    id: 'linear-api-key',
    description: 'Linear.app API Key (lin_api_ prefix)',
    pattern: /['"\`](lin_api_[A-Za-z0-9]{40,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'LINEAR_API_KEY',
    severity: 'critical',
  },
  // Notion Integration Token
  {
    id: 'notion-api-key',
    description: 'Notion Integration Token (secret_ prefix)',
    pattern: /(?:notion[_-]?(?:api[_-]?)?(?:key|token|secret)|NOTION_TOKEN|NOTION_API_KEY)\s*[:=]\s*['"\`](secret_[A-Za-z0-9]{43,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'NOTION_TOKEN',
    severity: 'critical',
  },
  // HubSpot API Key
  {
    id: 'hubspot-api-key',
    description: 'HubSpot API Key or Private App Access Token',
    pattern: /(?:hubspot[_-]?(?:api[_-]?key|private[_-]?app[_-]?token|access[_-]?token)|HUBSPOT_API_KEY|HUBSPOT_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{32,}|pat-na1-[A-Za-z0-9\-]{36,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'HUBSPOT_API_KEY',
    severity: 'critical',
  },
  // Zendesk API Token
  {
    id: 'zendesk-api-token',
    description: 'Zendesk API Token',
    pattern: /(?:zendesk[_-]?(?:api[_-]?)?token|ZENDESK_TOKEN|ZENDESK_API_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{40,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ZENDESK_API_TOKEN',
    severity: 'critical',
  },
  // Freshdesk API Key
  {
    id: 'freshdesk-api-key',
    description: 'Freshdesk API Key',
    pattern: /(?:freshdesk[_-]?(?:api[_-]?)?key|FRESHDESK_API_KEY)\s*[:=]\s*['"\`]([A-Za-z0-9]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'FRESHDESK_API_KEY',
    severity: 'critical',
  },
  // Zoom API Secret
  {
    id: 'zoom-api-secret',
    description: 'Zoom API Secret Key or Client Secret',
    pattern: /(?:zoom[_-]?(?:api[_-]?)?secret|ZOOM_API_SECRET|ZOOM_CLIENT_SECRET)\s*[:=]\s*['"\`]([A-Za-z0-9]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ZOOM_API_SECRET',
    severity: 'critical',
  },

  // Asana PAT
  {
    id: 'asana-personal-access-token',
    description: 'Asana Personal Access Token',
    pattern: /(?:asana[_-]?(?:personal[_-]?access[_-]?)?token|ASANA_TOKEN|ASANA_PAT)\s*[:=]\s*['"\`]([0-9]{1,}\/[A-Za-z0-9:]{30,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ASANA_TOKEN',
    severity: 'critical',
  },
  // Monday.com API Token
  {
    id: 'monday-api-token',
    description: 'Monday.com API Token',
    pattern: /(?:monday[_-]?(?:api[_-]?)?token|MONDAY_TOKEN|MONDAY_API_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{60,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'MONDAY_API_TOKEN',
    severity: 'critical',
  },
  // Spotify Client Secret
  {
    id: 'spotify-client-secret',
    description: 'Spotify API Client Secret',
    pattern: /(?:spotify[_-]?client[_-]?secret|SPOTIFY_CLIENT_SECRET)\s*[:=]\s*['"\`]([a-f0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SPOTIFY_CLIENT_SECRET',
    severity: 'critical',
  },
  // Twitter/X API Secret
  {
    id: 'twitter-api-secret',
    description: 'Twitter/X API Secret Key, Consumer Secret, or Bearer Token',
    pattern: /(?:twitter[_-]?(?:api[_-]?)?(?:secret|consumer[_-]?secret|bearer[_-]?token)|TWITTER_API_SECRET|TWITTER_CONSUMER_SECRET|TWITTER_BEARER_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9%\-_]{30,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'TWITTER_API_SECRET',
    severity: 'critical',
  },
  // Facebook/Meta App Secret
  {
    id: 'facebook-app-secret',
    description: 'Facebook / Meta App Secret',
    pattern: /(?:facebook[_-]?(?:app[_-]?)?secret|fb[_-]?app[_-]?secret|FACEBOOK_APP_SECRET|FB_APP_SECRET|META_APP_SECRET)\s*[:=]\s*['"\`]([a-f0-9]{32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'FACEBOOK_APP_SECRET',
    severity: 'critical',
  },
  // Instagram Access Token
  {
    id: 'instagram-access-token',
    description: 'Instagram Graph API Access Token',
    pattern: /(?:instagram[_-]?(?:access[_-]?)?token|INSTAGRAM_ACCESS_TOKEN|IG_ACCESS_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{20,}\.[A-Za-z0-9\-_]{40,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'INSTAGRAM_ACCESS_TOKEN',
    severity: 'high',
  },
  // Dropbox Access Token
  {
    id: 'dropbox-access-token',
    description: 'Dropbox OAuth2 Access Token (sl. prefix)',
    pattern: /(?:dropbox[_-]?(?:access[_-]?)?token|DROPBOX_TOKEN|DROPBOX_ACCESS_TOKEN)\s*[:=]\s*['"\`](sl\.[A-Za-z0-9\-_]{130,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DROPBOX_ACCESS_TOKEN',
    severity: 'critical',
  },
  // Box Developer Token
  {
    id: 'box-developer-token',
    description: 'Box.com Developer Token or App Access Token',
    pattern: /(?:box[_-]?(?:developer[_-]?|access[_-]?)?token|BOX_TOKEN|BOX_ACCESS_TOKEN|BOX_DEVELOPER_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9]{32,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'BOX_ACCESS_TOKEN',
    severity: 'critical',
  },

  // ── Shopify ───────────────────────────────────────────────────────────────────
  {
    id: 'shopify-access-token',
    description: 'Shopify Private App or Custom App Admin API Access Token (shpat_ / shpca_ prefix)',
    pattern: /['"`](shp(?:at|ca)_[A-Za-z0-9]{32})['"`]/,
    valueGroup: 1,
    envKeyPrefix: 'SHOPIFY_ACCESS_TOKEN',
    severity: 'critical',
  },
  {
    id: 'shopify-shared-secret',
    description: 'Shopify Partner / App Shared Secret used to verify webhook signatures',
    pattern: /(?:shopify[_-]?(?:shared[_-]?|webhook[_-]?)?secret|SHOPIFY_SHARED_SECRET|SHOPIFY_WEBHOOK_SECRET)\s*[:=]\s*['"`]([a-f0-9]{32})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SHOPIFY_SHARED_SECRET',
    severity: 'critical',
  },

  // ── PayPal ────────────────────────────────────────────────────────────────────
  {
    id: 'paypal-client-secret',
    description: 'PayPal OAuth2 Client Secret',
    pattern: /(?:paypal[_-]?client[_-]?secret|PAYPAL_CLIENT_SECRET)\s*[:=]\s*['"`]([A-Za-z0-9\-_.~]{20,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PAYPAL_CLIENT_SECRET',
    severity: 'critical',
  },
  {
    id: 'paypal-client-id',
    description: 'PayPal OAuth2 Client ID (App ID)',
    pattern: /(?:paypal[_-]?client[_-]?id|PAYPAL_CLIENT_ID)\s*[:=]\s*['"`]([A-Za-z0-9\-_.~]{40,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PAYPAL_CLIENT_ID',
    severity: 'high',
  },

  // ── npm / Registry ────────────────────────────────────────────────────────────
  {
    id: 'npmrc-auth-token',
    description: 'npm _authToken in .npmrc (new npm_... format or legacy UUID token)',
    pattern: /(?:_authToken\s*=\s*|authToken\s*[:=]\s*['"`]?)([A-Za-z0-9\-_.~]{8,}|npm_[A-Za-z0-9]{36})(?:['"`]|\s|$)/,
    valueGroup: 1,
    envKeyPrefix: 'NPM_AUTH_TOKEN',
    severity: 'critical',
  },

  // ── Sentry ────────────────────────────────────────────────────────────────────
  {
    id: 'sentry-dsn',
    description: 'Sentry DSN with embedded public key (exposes project endpoint)',
    pattern: /(?:sentry[_-]?dsn|SENTRY_DSN)\s*[:=]\s*['"`](https?:\/\/[A-Za-z0-9]+@o\d+\.ingest(?:\.us)?\.sentry\.io\/\d+)['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SENTRY_DSN',
    severity: 'high',
  },
  {
    id: 'sentry-auth-token',
    description: 'Sentry Auth Token (sntrys_ prefix — used for CI releases and source maps)',
    pattern: /['"`](sntrys_[A-Za-z0-9_]{64,})['"`]/,
    valueGroup: 1,
    envKeyPrefix: 'SENTRY_AUTH_TOKEN',
    severity: 'critical',
  },

  // ── Pusher ────────────────────────────────────────────────────────────────────
  {
    id: 'pusher-app-secret',
    description: 'Pusher Channels App Secret',
    pattern: /(?:pusher[_-]?(?:app[_-]?)?secret|PUSHER_APP_SECRET)\s*[:=]\s*['"`]([A-Za-z0-9]{20,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PUSHER_APP_SECRET',
    severity: 'critical',
  },
  {
    id: 'pusher-app-key',
    description: 'Pusher Channels App Key',
    pattern: /(?:pusher[_-]?app[_-]?key|PUSHER_APP_KEY)\s*[:=]\s*['"`]([A-Za-z0-9]{20,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PUSHER_APP_KEY',
    severity: 'high',
  },

  // ── Postmark ──────────────────────────────────────────────────────────────────
  {
    id: 'postmark-server-token',
    description: 'Postmark Server API Token (UUID format)',
    pattern: /(?:postmark[_-]?(?:server[_-]?)?(?:token|api[_-]?key)|POSTMARK_SERVER_TOKEN|POSTMARK_API_KEY)\s*[:=]\s*['"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'POSTMARK_SERVER_TOKEN',
    severity: 'critical',
  },

  // ── Mailchimp ─────────────────────────────────────────────────────────────────
  {
    id: 'mailchimp-api-key',
    description: 'Mailchimp API Key (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-usN format)',
    pattern: /['"`]([A-Za-z0-9]{32}-us\d{1,2})['"`]/,
    valueGroup: 1,
    envKeyPrefix: 'MAILCHIMP_API_KEY',
    severity: 'critical',
  },

  // ── Adyen ─────────────────────────────────────────────────────────────────────
  {
    id: 'adyen-api-key',
    description: 'Adyen Payment Gateway API Key',
    pattern: /(?:adyen[_-]?(?:api[_-]?)?key|ADYEN_API_KEY)\s*[:=]\s*['"`]([A-Za-z0-9+/=]{32,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ADYEN_API_KEY',
    severity: 'critical',
  },

  // ── Braintree Merchant ID ─────────────────────────────────────────────────────
  {
    id: 'braintree-merchant-id',
    description: 'Braintree Merchant ID',
    pattern: /(?:braintree[_-]?merchant[_-]?id|BRAINTREE_MERCHANT_ID)\s*[:=]\s*['"`]([A-Za-z0-9]{16,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'BRAINTREE_MERCHANT_ID',
    severity: 'medium',
  },

  // ── Linode / Akamai Cloud ─────────────────────────────────────────────────────
  {
    id: 'linode-personal-access-token',
    description: 'Linode / Akamai Cloud API Personal Access Token',
    pattern: /(?:linode[_-]?(?:api[_-]?)?token|LINODE_TOKEN|LINODE_API_TOKEN)\s*[:=]\s*['"`]([A-Za-z0-9]{64})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'LINODE_TOKEN',
    severity: 'critical',
  },

  // ── Vultr ─────────────────────────────────────────────────────────────────────
  {
    id: 'vultr-api-key',
    description: 'Vultr Cloud API Key (UUID v4 format)',
    pattern: /(?:vultr[_-]?(?:api[_-]?)?key|VULTR_API_KEY)\s*[:=]\s*['"`]([0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'VULTR_API_KEY',
    severity: 'critical',
  },

  // ── Scaleway ──────────────────────────────────────────────────────────────────
  {
    id: 'scaleway-secret-key',
    description: 'Scaleway Secret Key (UUID v4 — used with SCW_SECRET_KEY env var)',
    pattern: /(?:scaleway[_-]?secret[_-]?key|SCW_SECRET_KEY)\s*[:=]\s*['"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SCW_SECRET_KEY',
    severity: 'critical',
  },

  // ── Fly.io ────────────────────────────────────────────────────────────────────
  {
    id: 'fly-io-api-token',
    description: 'Fly.io Deploy / API Token (FlyV1 prefix)',
    pattern: /['"`](FlyV1\s[A-Za-z0-9+/=]{20,})['"`]/,
    valueGroup: 1,
    envKeyPrefix: 'FLY_API_TOKEN',
    severity: 'critical',
  },

  // ── Render ────────────────────────────────────────────────────────────────────
  {
    id: 'render-api-key',
    description: 'Render.com API Key (rnd_ prefix)',
    pattern: /['"`](rnd_[A-Za-z0-9]{40,})['"`]/,
    valueGroup: 1,
    envKeyPrefix: 'RENDER_API_KEY',
    severity: 'critical',
  },

  // ── Expo ──────────────────────────────────────────────────────────────────────
  {
    id: 'expo-access-token',
    description: 'Expo (React Native / EAS) Access Token (expo_ prefix)',
    pattern: /(?:['"`](expo_[A-Za-z0-9_]{40,})['"`]|(?:expo[_-]?(?:access[_-]?)?token|EXPO_TOKEN|EXPO_ACCESS_TOKEN)\s*[:=]\s*['"`]([A-Za-z0-9_]{20,})['"`])/i,
    valueGroup: 1,
    envKeyPrefix: 'EXPO_ACCESS_TOKEN',
    severity: 'critical',
  },
];
