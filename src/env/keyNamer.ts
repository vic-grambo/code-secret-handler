/**
 * Sanitizes a string to be a valid env variable name:
 *  - Upper-case
 *  - Only alphanumeric and underscores
 *  - Cannot start with a digit
 */
export function sanitizeEnvKey(key: string): string {
  let sanitized = key
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, '_')   // replace non-alphanum/underscore with _
    .replace(/^[0-9]+/, '_');       // cannot start with digits

  // Collapse multiple consecutive underscores
  sanitized = sanitized.replace(/__+/g, '_').replace(/^_|_$/g, '');

  return sanitized || 'SECRET';
}

/**
 * Generates a collision-safe env key from a base name and a set of already-used keys.
 * Appends _2, _3, ... until unique.
 */
export function makeUniqueKey(baseKey: string, usedKeys: Set<string>): string {
  const sanitized = sanitizeEnvKey(baseKey);
  if (!usedKeys.has(sanitized)) return sanitized;

  let suffix = 2;
  while (usedKeys.has(`${sanitized}_${suffix}`)) suffix++;
  return `${sanitized}_${suffix}`;
}
