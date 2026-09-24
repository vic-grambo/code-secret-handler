import { Rule } from '../../types';

/**
 * SSH and PEM private key patterns.
 */
export const sshRules: Rule[] = [
  {
    id: 'ssh-private-key-pem',
    description: 'SSH RSA Private Key (PEM block)',
    pattern: /(-----BEGIN RSA PRIVATE KEY-----[\s\S]{64,}-----END RSA PRIVATE KEY-----)/,
    valueGroup: 1,
    envKeyPrefix: 'SSH_RSA_PRIVATE_KEY',
    severity: 'critical',
  },
  {
    id: 'ssh-openssh-private-key',
    description: 'OpenSSH Private Key',
    pattern: /(-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{64,}-----END OPENSSH PRIVATE KEY-----)/,
    valueGroup: 1,
    envKeyPrefix: 'SSH_OPENSSH_PRIVATE_KEY',
    severity: 'critical',
  },
  {
    id: 'ssh-dsa-private-key',
    description: 'SSH DSA Private Key (PEM block)',
    pattern: /(-----BEGIN DSA PRIVATE KEY-----[\s\S]{64,}-----END DSA PRIVATE KEY-----)/,
    valueGroup: 1,
    envKeyPrefix: 'SSH_DSA_PRIVATE_KEY',
    severity: 'critical',
  },
  {
    id: 'ssh-ec-private-key',
    description: 'SSH EC Private Key (PEM block)',
    pattern: /(-----BEGIN EC PRIVATE KEY-----[\s\S]{64,}-----END EC PRIVATE KEY-----)/,
    valueGroup: 1,
    envKeyPrefix: 'SSH_EC_PRIVATE_KEY',
    severity: 'critical',
  },
  {
    id: 'ssh-private-key-inline',
    description: 'SSH private key assigned as an inline string variable',
    pattern: /(?:ssh[_-]?private[_-]?key|SSH_PRIVATE_KEY|id_rsa)\s*[:=]\s*['"`](-----BEGIN[^'"`]+-----END[^'"`]+-----)['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SSH_PRIVATE_KEY',
    severity: 'critical',
  },
];
