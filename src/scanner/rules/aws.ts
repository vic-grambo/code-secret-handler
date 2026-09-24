import { Rule } from '../../types';

/**
 * AWS credential patterns.
 */
export const awsRules: Rule[] = [
  {
    id: 'aws-access-key-id',
    description: 'AWS Access Key ID',
    // AWS access key IDs start with AKIA, ABIA, ACCA, or ASIA
    pattern: /(?:aws[_-]?access[_-]?key[_-]?id|aws[_-]?access[_-]?key)\s*[:=]\s*['"\`]?((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})['"\`]?/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_ACCESS_KEY_ID',
    severity: 'critical',
  },
  {
    id: 'aws-access-key-id-bare',
    description: 'Bare AWS Access Key ID (without variable name context)',
    pattern: /['"\`]((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})['"\`]/,
    valueGroup: 1,
    envKeyPrefix: 'AWS_ACCESS_KEY_ID',
    severity: 'critical',
  },
  {
    id: 'aws-secret-access-key',
    description: 'AWS Secret Access Key',
    pattern: /(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*['"\`]([A-Za-z0-9+/]{40})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_SECRET_ACCESS_KEY',
    severity: 'critical',
  },
  {
    id: 'aws-session-token',
    description: 'AWS Session Token',
    pattern: /(?:aws[_-]?session[_-]?token|aws[_-]?security[_-]?token)\s*[:=]\s*['"\`]([A-Za-z0-9+/=]{100,})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_SESSION_TOKEN',
    severity: 'critical',
  },
  {
    id: 'aws-account-id',
    description: 'AWS Account ID',
    pattern: /(?:aws[_-]?account[_-]?id|aws[_-]?account)\s*[:=]\s*['"\`]?(\d{12})['"\`]?/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_ACCOUNT_ID',
    severity: 'high',
  },
  {
    id: 'aws-mws-key',
    description: 'AWS MWS (Marketplace Web Service) Key',
    pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
    valueGroup: 0,
    envKeyPrefix: 'AWS_MWS_KEY',
    severity: 'critical',
  },
  {
    id: 'aws-region',
    description: 'AWS Region hardcoded assignment',
    pattern: /(?:aws[_-]?region)\s*[:=]\s*['"\`](us-east-[12]|us-west-[12]|eu-west-[123]|eu-central-1|ap-southeast-[12]|ap-northeast-[123]|sa-east-1|ca-central-1|ap-south-1|ap-east-1|me-south-1|af-south-1)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_REGION',
    severity: 'low',
  },
  {
    id: 'aws-arn',
    description: 'Hardcoded AWS ARN (resource identifier)',
    pattern: /(?:arn[_-]?value|resource[_-]?arn|target[_-]?arn|(?:sns|sqs|lambda|iam|s3)[_-]?arn)\s*[:=]\s*['"\`](arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^'"\`\s]+)['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_ARN',
    severity: 'medium',
  },
  {
    id: 'aws-s3-bucket',
    description: 'AWS S3 bucket name hardcoded assignment',
    pattern: /(?:s3[_-]?bucket(?:[_-]?name)?|bucket[_-]?name|AWS_S3_BUCKET)\s*[:=]\s*['"\`]([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'AWS_S3_BUCKET',
    severity: 'medium',
  },
  {
    id: 'aws-cloudfront-key-pair-id',
    description: 'AWS CloudFront Key Pair ID',
    pattern: /(?:cloudfront[_-]?key[_-]?pair[_-]?id|CLOUDFRONT_KEY_PAIR_ID)\s*[:=]\s*['"\`]([A-Z0-9]{14,20})['"\`]/i,
    valueGroup: 1,
    envKeyPrefix: 'CLOUDFRONT_KEY_PAIR_ID',
    severity: 'high',
  },
];
