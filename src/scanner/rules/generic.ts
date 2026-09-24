import { Rule } from '../../types';

/**
 * Generic secret patterns: API keys, passwords, tokens, secrets.
 * These patterns match common assignment patterns across all languages.
 *
 * Assignment forms covered:
 *   key = 'value'          (Python, JS, shell, YAML)
 *   key: 'value'           (YAML, JSON)
 *   define('KEY', 'value') (PHP)
 *   KEY=value              (.env files)
 */
export const genericRules: Rule[] = [
  // ── PHP define() ────────────────────────────────────────────────────────────────
  {
    id: 'php-define-secret',
    description: 'PHP define() call with any secret-looking key name',
    // Matches: define('SOME_SECRET_KEY', 'value') or define("KEY", 'value')
    pattern: /define\s*\(\s*['"]((?:[A-Z][A-Z0-9_]*_)?(?:SECRET|PASSWORD|PASSWD|API_KEY|API_SECRET|AUTH_KEY|ACCESS_TOKEN|REFRESH_TOKEN|SESSION_SECRET|OAUTH[0-9]?_CLIENT_SECRET|PRIVATE_KEY|TOKEN|INTEGRATION_KEY|STORAGE_KEY|VAULT_TOKEN|CLIENT_SECRET)[A-Z0-9_]*)['"\`]\s*,\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 2,
    envKeyPrefix: 'SECRET',
    severity: 'critical',
  },
  {
    id: 'php-define-any-key',
    description: 'PHP define() with any variable name ending in _KEY, _SECRET, _TOKEN, _PASSWORD',
    // Broad fallback: any define('*_PASSWORD', ...), define('*_SECRET', ...), etc.
    pattern: /define\s*\(\s*['"\`]([A-Za-z][A-Za-z0-9_]{2,}(?:_(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AUTH_KEY|STORAGE_KEY|ACCESS_KEY|ACCESS_TOKEN|REFRESH_TOKEN|INTEGRATION_KEY|VAULT_TOKEN)))['"\`]\s*,\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 2,
    envKeyPrefix: 'SECRET',
    severity: 'critical',
  },
  // ── Uppercase _PASSWORD variable names (any service) ─────────────────────────────
  {
    id: 'uppercase-password-var',
    description: 'Any uppercase *_PASSWORD or *_PASSWD variable assignment',
    pattern: /\b([A-Z][A-Z0-9_]*_PASS(?:W(?:OR)?D)?)\s*=\s*['"\`]([^'"\`\n]{4,})['"\`]/,
    valueGroup: 2,
    envKeyPrefix: 'PASSWORD',
    severity: 'critical',
  },
  // ── Uppercase _SECRET variable names (any service) ──────────────────────────────
  {
    id: 'uppercase-secret-var',
    description: 'Any uppercase *_SECRET variable assignment',
    pattern: /\b([A-Z][A-Z0-9_]*_SECRET)\s*=\s*['"\`]([^'"\`\n]{4,})['"\`]/,
    valueGroup: 2,
    envKeyPrefix: 'SECRET',
    severity: 'critical',
  },
  // ── Uppercase _KEY variable names (any service) ─────────────────────────────────
  {
    id: 'uppercase-key-var',
    description: 'Any uppercase *_KEY variable assignment (min 16 chars to avoid false positives)',
    pattern: /\b([A-Z][A-Z0-9_]*_(?:API_)?KEY)\s*=\s*['"\`]([A-Za-z0-9!@#\$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]{8,})['"\`]/,
    valueGroup: 2,
    envKeyPrefix: 'API_KEY',
    severity: 'high',
  },
  // ── Uppercase _TOKEN variable names (access / refresh) ────────────────────────
  {
    id: 'uppercase-token-var',
    description: 'Any uppercase *_TOKEN variable with a long token value',
    // Require the value to look like a real token (letters+digits, 16+ chars)
    pattern: /\b([A-Z][A-Z0-9_]*_(?:ACCESS_|REFRESH_|AUTH_|API_|INTEGRATION_)?TOKEN)\s*=\s*['"\`]([A-Za-z0-9\-_.~+/=!]{16,})['"\`]/,
    valueGroup: 2,
    envKeyPrefix: 'TOKEN',
    severity: 'high',
  },
  // ── Existing patterns below ────────────────────────────────────────────────────────────
  {
    id: 'generic-api-key',
    description: 'Generic API key assignment',
    pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{16,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'API_KEY',
    severity: 'high',
  },
  {
    id: 'generic-api-secret',
    description: 'Generic API secret assignment',
    pattern: /(?:api[_-]?secret|apisecret)\s*[:=]\s*['"\`]([A-Za-z0-9\-_+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'API_SECRET',
    severity: 'critical',
  },
  {
    id: 'generic-secret-key',
    description: 'Generic secret key assignment',
    pattern: /(?:secret[_-]?key|secretkey)\s*[:=]\s*['"\`]([A-Za-z0-9\-_+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SECRET_KEY',
    severity: 'critical',
  },
  {
    id: 'generic-secret',
    description: 'Generic secret/password variable',
    pattern: /(?:^|[\s,({])(?:secret|password|passwd|pwd|pass)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SECRET',
    severity: 'critical',
  },
  {
    id: 'generic-token',
    description: 'Generic token assignment',
    pattern: /(?:token|auth_token|access_token|refresh_token)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{16,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'TOKEN',
    severity: 'high',
  },
  {
    id: 'generic-bearer-token',
    description: 'Bearer token in Authorization header value',
    pattern: /(?:authorization|auth[_-]?header)\s*[:=]\s*['"\`](Bearer\s+[A-Za-z0-9\-_.~+/=]{16,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'BEARER_TOKEN',
    severity: 'critical',
  },
  {
    id: 'generic-private-key-value',
    description: 'Generic private key value',
    pattern: /(?:private[_-]?key|priv[_-]?key)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{16,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PRIVATE_KEY',
    severity: 'critical',
  },
  {
    id: 'generic-client-secret',
    description: 'OAuth client secret',
    pattern: /client[_-]?secret\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CLIENT_SECRET',
    severity: 'critical',
  },
  {
    id: 'generic-encryption-key',
    description: 'Encryption or cipher key',
    pattern: /(?:encryption[_-]?key|cipher[_-]?key|encrypt[_-]?key|aes[_-]?key)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ENCRYPTION_KEY',
    severity: 'critical',
  },
  {
    id: 'generic-hmac-key',
    description: 'HMAC or hash signing key',
    pattern: /(?:hmac[_-]?(?:secret|key)|hash[_-]?key|signing[_-]?key|sign[_-]?key)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'HMAC_KEY',
    severity: 'critical',
  },
  {
    id: 'generic-auth-password',
    description: 'Auth password field',
    pattern: /(?:auth[_-]?password|auth[_-]?pass|admin[_-]?password|admin[_-]?pass)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AUTH_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'generic-root-password',
    description: 'Root or master password assignment',
    pattern: /(?:root[_-]?password|root[_-]?pass|master[_-]?password|master[_-]?pass)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ROOT_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'generic-service-password',
    description: 'Service account or service password',
    pattern: /(?:service[_-]?password|service[_-]?pass|svc[_-]?password|svc[_-]?pass)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SERVICE_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'generic-app-secret',
    description: 'Application secret or app key',
    pattern: /(?:app[_-]?secret|app[_-]?key|application[_-]?secret)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'APP_SECRET',
    severity: 'critical',
  },
  {
    id: 'generic-master-key',
    description: 'Master key or root key assignment',
    pattern: /(?:master[_-]?key|root[_-]?key)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'MASTER_KEY',
    severity: 'critical',
  },
  {
    id: 'generic-webhook-secret',
    description: 'Webhook secret or signing secret',
    pattern: /(?:webhook[_-]?secret|signing[_-]?secret|consumer[_-]?secret)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'WEBHOOK_SECRET',
    severity: 'critical',
  },
  {
    id: 'generic-license-key',
    description: 'License key or activation key',
    pattern: /(?:license[_-]?key|activation[_-]?key|product[_-]?key|serial[_-]?key)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'LICENSE_KEY',
    severity: 'high',
  },
  {
    id: 'generic-ssh-password',
    description: 'SSH, FTP, or SFTP password',
    pattern: /(?:ssh[_-]?pass(?:word)?|ftp[_-]?pass(?:word)?|sftp[_-]?pass(?:word)?)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SSH_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'generic-basic-auth',
    description: 'HTTP Basic Auth credentials embedded in a URL',
    pattern: /https?:\/\/([A-Za-z0-9\-_.~%]+:[^@\s'"\`]{4,})@[A-Za-z0-9\-.]+/,
    valueGroup: 1,
    envKeyPrefix: 'BASIC_AUTH_CREDENTIALS',
    severity: 'critical',
  },
  {
    id: 'generic-connection-string',
    description: 'Generic connection string with embedded credentials',
    pattern: /(?:connection[_-]?string|conn[_-]?str|connstring)\s*[:=]\s*['"\`]([^'"\`\n]{12,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CONNECTION_STRING',
    severity: 'critical',
  },
  {
    id: 'generic-private-token',
    description: 'Private or internal API token variable',
    pattern: /(?:private[_-]?token|internal[_-]?token|server[_-]?token|service[_-]?token)\s*[:=]\s*['"\`]([A-Za-z0-9\-_.~+/=]{16,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PRIVATE_TOKEN',
    severity: 'critical',
  },

  // API key in HTTP header assignment
  {
    id: 'generic-api-key-header',
    description: 'API key passed as a raw HTTP header value (X-API-Key / X-Auth-Key)',
    pattern: /(?:'X-API-Key'|"X-API-Key"|'X-Auth-Key'|"X-Auth-Key")\s*[:=,>]+\s*['"\`]([A-Za-z0-9\-_.~+\/=]{16,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'API_KEY',
    severity: 'critical',
  },
  // Unquoted .env secret
  {
    id: 'generic-secret-env-unquoted',
    description: 'Unquoted secret value in .env-style assignment (no surrounding quotes)',
    pattern: /^([A-Z][A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API_KEY|TOKEN|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)=([A-Za-z0-9+\/\-_!@#$%^&*]{12,})$/m,
    valueGroup: 2,
    envKeyPrefix: 'SECRET',
    severity: 'critical',
  },
  // Hardcoded AES IV
  {
    id: 'generic-encryption-iv',
    description: 'Hardcoded AES Initialization Vector (IV) — 16 or 32 bytes as hex',
    pattern: /(?:iv|initialization[_-]?vector|aes[_-]?iv|cipher[_-]?iv)\s*[:=]\s*['"\`]([A-Fa-f0-9]{32}|[A-Fa-f0-9]{64})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ENCRYPTION_IV',
    severity: 'high',
  },
  // TOTP / 2FA shared secret
  {
    id: 'generic-totp-secret',
    description: 'TOTP/2FA shared secret (Base32 format used by authenticator apps)',
    pattern: /(?:totp[_-]?secret|otp[_-]?secret|two[_-]?fa[_-]?secret|mfa[_-]?secret|authenticator[_-]?secret|TOTP_SECRET|OTP_SECRET|MFA_SECRET)\s*[:=]\s*['"\`]([A-Z2-7]{16,32})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'TOTP_SECRET',
    severity: 'critical',
  },

  // ── AES encryption key ────────────────────────────────────────────────────────
  {
    id: 'generic-aes-key',
    description: 'Hardcoded AES encryption key (128-bit / 192-bit / 256-bit as hex string)',
    // 128-bit = 32 hex chars, 192-bit = 48 hex chars, 256-bit = 64 hex chars
    pattern: /(?:aes[_-]?(?:256[_-]?|192[_-]?|128[_-]?)?(?:encryption[_-]?)?key|AES_KEY|AES_SECRET_KEY|AES_ENCRYPTION_KEY)\s*[:=]\s*['"`]([A-Fa-f0-9]{32}|[A-Fa-f0-9]{48}|[A-Fa-f0-9]{64})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AES_KEY',
    severity: 'critical',
  },

  // ── HMAC secret ───────────────────────────────────────────────────────────────
  {
    id: 'generic-hmac-secret',
    description: 'Hardcoded HMAC signing secret (SHA-256 / SHA-512)',
    pattern: /(?:hmac[_-]?(?:secret|key|signing[_-]?key)|HMAC_SECRET|HMAC_KEY)\s*[:=]\s*['"`]([A-Za-z0-9+/=\-_]{16,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'HMAC_SECRET',
    severity: 'critical',
  },

  // ── Generic encryption / decryption key ──────────────────────────────────────
  {
    id: 'generic-encryption-key',
    description: 'Generic hardcoded encryption or decryption key variable',
    pattern: /(?:encrypt(?:ion)?[_-]?key|decrypt(?:ion)?[_-]?key|cipher[_-]?key|ENCRYPTION_KEY|DECRYPTION_KEY|CIPHER_KEY)\s*[:=]\s*['"`]([A-Za-z0-9+/=\-_]{16,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ENCRYPTION_KEY',
    severity: 'critical',
  },
];
