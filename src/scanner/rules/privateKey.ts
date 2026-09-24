import { Rule } from '../../types';

/**
 * Generic PEM private key and certificate patterns.
 */
export const privateKeyRules: Rule[] = [
  {
    id: 'pem-private-key',
    description: 'Generic PEM Private Key block',
    pattern: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PKCS8 )?PRIVATE KEY-----[\s\S]{64,}-----END (?:RSA |EC |DSA |OPENSSH |PKCS8 )?PRIVATE KEY-----)/,
    valueGroup: 1,
    envKeyPrefix: 'PEM_PRIVATE_KEY',
    severity: 'critical',
  },
  {
    id: 'pem-certificate',
    description: 'PEM Certificate block',
    pattern: /(-----BEGIN CERTIFICATE-----[\s\S]{64,}-----END CERTIFICATE-----)/,
    valueGroup: 1,
    envKeyPrefix: 'PEM_CERTIFICATE',
    severity: 'medium',
  },
  {
    id: 'pgp-private-key',
    description: 'PGP / GPG Private Key Block',
    pattern: /(-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{64,}-----END PGP PRIVATE KEY BLOCK-----)/,
    valueGroup: 1,
    envKeyPrefix: 'PGP_PRIVATE_KEY',
    severity: 'critical',
  },
  {
    id: 'pkcs12-password',
    description: 'PKCS12 / PFX keystore password',
    pattern: /(?:pkcs12[_-]?password|pfx[_-]?password|keystore[_-]?password|KEY_STORE_PASSWORD|PKCS12_PASSWORD)\s*[:=]\s*['"`]([^'"`\n]{4,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PKCS12_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'ssl-key-path',
    description: 'SSL/TLS private key file path',
    pattern: /(?:ssl[_-]?key(?:[_-]?file)?|tls[_-]?key(?:[_-]?file)?|SSL_KEY_FILE)\s*[:=]\s*['"`]([^'"`\n]+\.(?:key|pem))['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SSL_KEY_FILE',
    severity: 'medium',
  },

  // ── age encryption tool secret key ───────────────────────────────────────────
  {
    id: 'age-secret-key',
    description: 'age encryption tool secret key (AGE-SECRET-KEY-1 Bech32 format)',
    // age secret keys are Bech32-encoded and always start with AGE-SECRET-KEY-1
    // followed by 58 uppercase alphanumeric Bech32 chars
    pattern: /(AGE-SECRET-KEY-1[A-Z0-9]{58})/,
    valueGroup: 1,
    envKeyPrefix: 'AGE_SECRET_KEY',
    severity: 'critical',
  },

];
