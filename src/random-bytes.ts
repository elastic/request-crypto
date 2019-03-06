import * as crypto from 'crypto';

export const KEY_LENGTH_IN_BYTES = 32;

export function generatePassphrase(): Buffer {
  return crypto.randomBytes(KEY_LENGTH_IN_BYTES);
}
