import * as crypto from 'crypto';

const KEY_LENGTH_IN_BYTES = 32;

export function generatePassphrase(): string {
  return crypto.randomBytes(KEY_LENGTH_IN_BYTES).toString('base64');
}
