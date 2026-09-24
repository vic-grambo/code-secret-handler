import { Rule } from '../../types';

/**
 * Google Cloud Platform credential patterns.
 */
export const gcpRules: Rule[] = [
  {
    id: 'gcp-api-key',
    description: 'Google Cloud / Firebase API Key',
    pattern: /(?:google[_-]?api[_-]?key|gcp[_-]?api[_-]?key|firebase[_-]?api[_-]?key|GOOGLE_API_KEY)\s*[:=]\s*['"\`](AIza[0-9A-Za-z\-_]{35})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GOOGLE_API_KEY',
    severity: 'critical',
  },
  {
    id: 'gcp-api-key-bare',
    description: 'Bare Google API Key (AIza... without variable name context)',
    pattern: /['"\`](AIza[0-9A-Za-z\-_]{35})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'GOOGLE_API_KEY',
    severity: 'critical',
  },
  {
    id: 'gcp-oauth-client-id',
    description: 'Google OAuth 2.0 Client ID',
    pattern: /(?:google[_-]?client[_-]?id|gcp[_-]?client[_-]?id)\s*[:=]\s*['"\`](\d+-[A-Za-z0-9_]+\.apps\.googleusercontent\.com)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GOOGLE_CLIENT_ID',
    severity: 'high',
  },
  {
    id: 'gcp-oauth-client-secret',
    description: 'Google OAuth 2.0 Client Secret',
    pattern: /(?:google[_-]?client[_-]?secret|gcp[_-]?client[_-]?secret)\s*[:=]\s*['"\`](GOCSPX-[A-Za-z0-9\-_]{28})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GOOGLE_CLIENT_SECRET',
    severity: 'critical',
  },
  {
    id: 'gcp-service-account-key',
    description: 'GCP Service Account private_key_id field',
    pattern: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/i,
    valueGroup: 1,
    envKeyPrefix: 'GCP_PRIVATE_KEY_ID',
    severity: 'critical',
  },
  {
    id: 'gcp-service-account-email',
    description: 'GCP Service Account email',
    pattern: /"client_email"\s*:\s*"([^"]+@[^"]+\.iam\.gserviceaccount\.com)"/i,
    valueGroup: 1,
    envKeyPrefix: 'GCP_CLIENT_EMAIL',
    severity: 'high',
  },
  {
    id: 'gcp-project-id',
    description: 'GCP Project ID hardcoded assignment',
    pattern: /(?:google[_-]?cloud[_-]?project|gcp[_-]?project[_-]?id|GOOGLE_CLOUD_PROJECT)\s*[:=]\s*['"\`]([a-z][a-z0-9\-]{4,28}[a-z0-9])['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GCP_PROJECT_ID',
    severity: 'medium',
  },
  {
    id: 'google-recaptcha-secret',
    description: 'Google reCAPTCHA Secret Key',
    pattern: /(?:recaptcha[_-]?secret[_-]?key|recaptcha[_-]?secret)\s*[:=]\s*['"\`](6[A-Za-z0-9_\-]{39})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'RECAPTCHA_SECRET_KEY',
    severity: 'high',
  },
  {
    id: 'google-maps-api-key',
    description: 'Google Maps / Places API Key (assigned to maps-specific variable)',
    pattern: /(?:google[_-]?maps[_-]?(?:api[_-]?)?key|maps[_-]?api[_-]?key|GOOGLE_MAPS_API_KEY|MAPS_API_KEY)\s*[:=]\s*['"\`](AIza[0-9A-Za-z\-_]{35})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GOOGLE_MAPS_API_KEY',
    severity: 'high',
  },
  {
    id: 'gcp-application-credentials',
    description: 'GOOGLE_APPLICATION_CREDENTIALS file path',
    pattern: /(?:GOOGLE_APPLICATION_CREDENTIALS|google[_-]?application[_-]?credentials)\s*[:=]\s*['"\`]([^'"\`\n]{4,}\.json)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'GOOGLE_APPLICATION_CREDENTIALS',
    severity: 'high',
  },
  {
    id: 'firebase-database-url',
    description: 'Firebase Realtime Database URL',
    pattern: /(?:firebase[_-]?(?:database[_-]?)?url|FIREBASE_DATABASE_URL)\s*[:=]\s*['"\`](https:\/\/[a-z0-9\-]+(?:-default-rtdb)?\.firebaseio\.com)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'FIREBASE_DATABASE_URL',
    severity: 'high',
  },

  // ── Firebase / GCP Service Account private_key field ─────────────────────────
  {
    id: 'firebase-admin-sdk-private-key',
    description: 'Firebase Admin SDK / GCP Service Account private_key value (inline JSON field)',
    // Complements the existing gcp-service-account-key which only catches private_key_id.
    // This rule catches the actual RSA private key value stored in the "private_key" JSON field.
    pattern: /"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----\\n?)"/,
    valueGroup: 1,
    envKeyPrefix: 'FIREBASE_PRIVATE_KEY',
    severity: 'critical',
  },

];
