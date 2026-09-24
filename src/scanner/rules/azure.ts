import { Rule } from '../../types';

/**
 * Microsoft Azure credential patterns.
 */
export const azureRules: Rule[] = [
  {
    id: 'azure-storage-connection-string',
    description: 'Azure Storage Connection String',
    pattern: /(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};[^\s'"]*)/ ,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_STORAGE_CONNECTION_STRING',
    severity: 'critical',
  },
  {
    id: 'azure-storage-account-key',
    description: 'Azure Storage Account Key',
    pattern: /(?:azure[_-]?storage[_-]?(?:account[_-]?)?key|AccountKey|AZURE_STORAGE_KEY)\s*[:=,]\s*['"\`]([A-Za-z0-9+/\s=]{40,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_STORAGE_ACCOUNT_KEY',
    severity: 'critical',
  },
  {
    id: 'azure-sas-token',
    description: 'Azure Shared Access Signature (SAS) Token',
    pattern: /(?:sas[_-]?token|azure[_-]?sas)\s*[:=]\s*['"\`](sv=\d{4}-\d{2}-\d{2}&[^'"\`\s]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_SAS_TOKEN',
    severity: 'critical',
  },
  {
    id: 'azure-client-secret',
    description: 'Azure AD Application Client Secret',
    // Also handles define('AZURE_CLIENT_SECRET', '...') PHP form
    pattern: /(?:define\s*\(\s*['"\`]AZURE_CLIENT_SECRET['"\`]\s*,\s*|(?:azure[_-]?client[_-]?secret|AZURE_CLIENT_SECRET)\s*[:=]\s*)['"\`]([A-Za-z0-9~.\-_]{8,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_CLIENT_SECRET',
    severity: 'critical',
  },
  {
    id: 'azure-client-id',
    description: 'Azure AD Application Client ID (UUID)',
    // Also handles define('AZURE_CLIENT_ID', 'uuid') PHP form
    pattern: /(?:define\s*\(\s*['"\`]AZURE_CLIENT_ID['"\`]\s*,\s*|(?:azure[_-]?client[_-]?id|AZURE_CLIENT_ID)\s*[:=]\s*)['"\`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_CLIENT_ID',
    severity: 'high',
  },
  {
    id: 'azure-tenant-id',
    description: 'Azure Tenant ID (UUID)',
    // Also handles define('AZURE_TENANT_ID', 'uuid') PHP form
    pattern: /(?:define\s*\(\s*['"\`]AZURE_TENANT_ID['"\`]\s*,\s*|(?:azure[_-]?tenant[_-]?id|AZURE_TENANT_ID)\s*[:=]\s*)['"\`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_TENANT_ID',
    severity: 'high',
  },
  {
    id: 'azure-servicebus-connection-string',
    description: 'Azure Service Bus Connection String',
    pattern: /(Endpoint=sb:\/\/[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^'"\`\s]+)/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_SERVICEBUS_CONNECTION_STRING',
    severity: 'critical',
  },
  {
    id: 'azure-cosmos-key',
    description: 'Azure CosmosDB Account Key',
    pattern: /(?:cosmos[_-]?(?:db[_-]?)?key|azure[_-]?cosmos[_-]?key)\s*[:=]\s*['"\`]([A-Za-z0-9+/=]{88})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_COSMOS_KEY',
    severity: 'critical',
  },

  // ── Azure DevOps ─────────────────────────────────────────────────────────────
  {
    id: 'azure-devops-pat',
    description: 'Azure DevOps Personal Access Token (base64-encoded, 52 chars)',
    // Azure DevOps PATs are base64-encoded strings typically 52 characters long
    pattern: /(?:azure[_-]?devops[_-]?(?:pat|token)|AZURE_DEVOPS_PAT|AZURE_DEVOPS_TOKEN|ADO_PAT)\s*[:=]\s*['"`]([A-Za-z0-9+/]{52}={0,2})['"`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AZURE_DEVOPS_PAT',
    severity: 'critical',
  },

];
