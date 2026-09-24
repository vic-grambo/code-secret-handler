import { Rule } from '../../types';

/**
 * Network, infrastructure, and communication credential patterns.
 * Covers: SMTP, proxy, VPN, Twilio SMS, mail servers, webhooks, etc.
 */
export const networkRules: Rule[] = [
  // ── SMTP / Email server ─────────────────────────────────────────────────────────
  {
    id: 'smtp-password',
    description: 'SMTP server password or auth credentials',
    pattern: /(?:smtp[_-]?(?:pass(?:word)?|auth[_-]?pass(?:word)?)|SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASSWORD)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SMTP_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'smtp-uri',
    description: 'SMTP URI with embedded credentials',
    pattern: /(?:smtp[_-]?(?:url|uri)|SMTP_URL|EMAIL_SERVER|MAIL_URL)\s*[:=]\s*['"\`](smtps?:\/\/[^'"\`\s]+:[^'"\`\s]+@[^'"\`\s]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SMTP_URL',
    severity: 'critical',
  },
  {
    id: 'smtp-user',
    description: 'SMTP username assignment',
    pattern: /(?:smtp[_-]?user(?:name)?|SMTP_USER(?:NAME)?|MAIL_USER(?:NAME)?|EMAIL_USER(?:NAME)?)\s*[:=]\s*['"\`]([^'"\`\n]{2,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SMTP_USER',
    severity: 'medium',
  },
  // ── Proxy / VPN ───────────────────────────────────────────────────────────────
  {
    id: 'proxy-url-with-creds',
    description: 'Proxy URL with embedded username/password',
    pattern: /(?:http[s]?[_-]?proxy|proxy[_-]?url|HTTPS?_PROXY|ALL_PROXY)\s*[:=]\s*['"\`](https?:\/\/[^'"\`\s]+:[^'"\`\s]+@[^'"\`\s]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PROXY_URL',
    severity: 'critical',
  },
  {
    id: 'proxy-password',
    description: 'Proxy server password',
    pattern: /(?:proxy[_-]?pass(?:word)?|PROXY_PASSWORD)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'PROXY_PASSWORD',
    severity: 'critical',
  },
  // ── CI/CD secrets ──────────────────────────────────────────────────────────────
  {
    id: 'ci-deploy-token',
    description: 'CI/CD deploy token or secret',
    pattern: /(?:ci[_-]?(?:deploy[_-]?)?(?:token|secret|key)|deploy[_-]?(?:token|key|secret)|DEPLOY_TOKEN|CI_DEPLOY_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9\-_]{16,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'DEPLOY_TOKEN',
    severity: 'critical',
  },
  {
    id: 'github-actions-secret',
    description: 'GitHub Actions secret reference used as a hardcoded value',
    pattern: /(?:ACTIONS_RUNNER_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_RUNTIME_TOKEN)\s*[:=]\s*['"\`]([A-Za-z0-9+/=]{20,})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'GITHUB_ACTIONS_TOKEN',
    severity: 'critical',
  },
  // ── Apple / iOS ───────────────────────────────────────────────────────────────
  {
    id: 'apple-private-key-id',
    description: 'Apple APNs / App Store Connect Private Key ID',
    pattern: /(?:apple[_-]?(?:private[_-]?)?key[_-]?id|APPLE_KEY_ID|APP_STORE_CONNECT_KEY_ID)\s*[:=]\s*['"\`]([A-Z0-9]{10})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'APPLE_KEY_ID',
    severity: 'high',
  },
  {
    id: 'apple-team-id',
    description: 'Apple Developer Team ID',
    pattern: /(?:apple[_-]?team[_-]?id|APPLE_TEAM_ID|TEAM_ID)\s*[:=]\s*['"\`]([A-Z0-9]{10})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'APPLE_TEAM_ID',
    severity: 'medium',
  },
  // ── Webhook URLs (generic) ─────────────────────────────────────────────────────
  {
    id: 'generic-webhook-url',
    description: 'Hardcoded webhook URL with embedded token',
    pattern: /(?:webhook[_-]?url|WEBHOOK_URL)\s*[:=]\s*['"\`](https?:\/\/[^'"\`\s]{20,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'WEBHOOK_URL',
    severity: 'high',
  },
  // ── LDAP credentials ───────────────────────────────────────────────────────────
  {
    id: 'ldap-bind-password',
    description: 'LDAP bind password',
    pattern: /(?:ldap[_-]?(?:bind[_-]?)?pass(?:word)?|LDAP_BIND_PASSWORD|LDAP_PASSWORD)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'LDAP_PASSWORD',
    severity: 'critical',
  },
  {
    id: 'ldap-uri',
    description: 'LDAP connection URI',
    pattern: /(?:ldap[_-]?(?:url|uri)|LDAP_URL|LDAP_URI)\s*[:=]\s*['"\`](ldaps?:\/\/[^'"\`\s]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'LDAP_URL',
    severity: 'medium',
  },

  // Kubernetes Service Account Token
  {
    id: 'kubernetes-service-account-token',
    description: 'Kubernetes Service Account Bearer Token (hardcoded JWT)',
    pattern: /(?:k8s[_-]?(?:service[_-]?account[_-]?)?token|kube(?:rnetes)?[_-]?(?:service[_-]?account[_-]?)?token|K8S_TOKEN|KUBE_TOKEN)\s*[:=]\s*['"\`](eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+\/=]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'K8S_SERVICE_ACCOUNT_TOKEN',
    severity: 'critical',
  },
  // Ansible Vault Password
  {
    id: 'ansible-vault-password',
    description: 'Ansible Vault password variable',
    pattern: /(?:ansible[_-]?vault[_-]?pass(?:word)?|ANSIBLE_VAULT_PASSWORD|vault[_-]?pass(?:word)?)\s*[:=]\s*['"\`]([^'"\`\n]{4,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'ANSIBLE_VAULT_PASSWORD',
    severity: 'critical',
  },
  // SonarQube / SonarCloud token
  {
    id: 'sonarqube-token',
    description: 'SonarQube or SonarCloud analysis token (squ_ prefix)',
    pattern: /(?:sonar(?:qube|cloud)?[_-]?token|SONAR_TOKEN|SONARQUBE_TOKEN)\s*[:=]\s*['"\`](squ_[A-Za-z0-9]{40,}|[A-Za-z0-9]{40,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'SONAR_TOKEN',
    severity: 'critical',
  },
  // CircleCI Personal API Token
  {
    id: 'circleci-personal-token',
    description: 'CircleCI Personal API Token',
    pattern: /(?:circleci[_-]?(?:personal[_-]?)?(?:api[_-]?)?token|CIRCLE_TOKEN|CIRCLECI_TOKEN)\s*[:=]\s*['"\`]([a-f0-9]{40})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CIRCLECI_TOKEN',
    severity: 'critical',
  },

  // ── Jenkins ───────────────────────────────────────────────────────────────────
  {
    id: 'jenkins-api-token',
    description: 'Jenkins User API Token',
    pattern: /(?:jenkins[_-]?(?:api[_-]?)?(?:token|key)|JENKINS_API_TOKEN|JENKINS_TOKEN)\s*[:=]\s*['"`]([A-Za-z0-9]{32,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'JENKINS_API_TOKEN',
    severity: 'critical',
  },

  // ── Travis CI ─────────────────────────────────────────────────────────────────
  {
    id: 'travis-ci-token',
    description: 'Travis CI API Token',
    pattern: /(?:travis[_-]?(?:ci[_-]?)?(?:api[_-]?)?token|TRAVIS_TOKEN|TRAVIS_CI_TOKEN)\s*[:=]\s*['"`]([A-Za-z0-9\-_]{22,})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'TRAVIS_CI_TOKEN',
    severity: 'critical',
  },

];
