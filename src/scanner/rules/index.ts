import { Rule } from '../../types';
import { genericRules } from './generic';
import { awsRules } from './aws';
import { gcpRules } from './gcp';
import { azureRules } from './azure';
import { databaseRules } from './database';
import { jwtRules } from './jwt';
import { sshRules } from './ssh';
import { privateKeyRules } from './privateKey';
import { cloudRules } from './cloud';
import { networkRules } from './network';

/**
 * All detection rules combined in a single flat array.
 * Order matters: more specific rules should come before generic ones.
 */
export const ALL_RULES: Rule[] = [
  ...awsRules,
  ...gcpRules,
  ...azureRules,
  ...cloudRules,
  ...databaseRules,
  ...jwtRules,
  ...sshRules,
  ...privateKeyRules,
  ...networkRules,
  ...genericRules,
];

export {
  genericRules,
  awsRules,
  gcpRules,
  azureRules,
  databaseRules,
  jwtRules,
  sshRules,
  privateKeyRules,
  cloudRules,
  networkRules,
};
