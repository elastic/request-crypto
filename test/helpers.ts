import _makeAESCryptoWith, { Crypto, CryptoOptions } from '@elastic/node-crypto';
import { CompactEncrypt, importJWK } from 'jose';

import {
  CONTENT_ENCRYPTION_ALGORITHM,
  generatePassphrase,
  LEGACY_KEY_WRAP_ALGORITHM,
  packBody,
  PublicJWK,
} from '../src';

const makeAESCryptoWith: (opts: CryptoOptions) => Crypto =
  (_makeAESCryptoWith as any).default || _makeAESCryptoWith;

export const publicComponents = ['kty', 'kid', 'use', 'alg', 'e', 'n'];
export const privateComponents = [
  'kty',
  'kid',
  'use',
  'alg',
  'e',
  'n',
  'd',
  'p',
  'q',
  'dp',
  'dq',
  'qi',
];

/**
 * Builds a request body exactly the way a sender running request-crypto 2.x does: the payload is
 * AES encrypted, and the AES passphrase is wrapped with the legacy "RSA-OAEP" (SHA-1) key wrap.
 *
 * This is the traffic an upgraded receiver has to keep decrypting for as long as any un-upgraded
 * sender exists, so it is worth simulating end to end rather than only through frozen vectors.
 */
export async function encryptWithLegacyKeyWrap(
  publicJwk: PublicJWK,
  kid: string,
  input: any
): Promise<string> {
  const AESKeyBuffer = generatePassphrase();
  const AES = makeAESCryptoWith({ encryptionKey: AESKeyBuffer });
  const encryptedPayload = await AES.encrypt(input);
  const publicKey = await importJWK(
    publicJwk as Parameters<typeof importJWK>[0],
    LEGACY_KEY_WRAP_ALGORITHM
  );
  const encryptedAESKey = await new CompactEncrypt(Uint8Array.from(AESKeyBuffer))
    .setProtectedHeader({
      zip: 'DEF',
      enc: CONTENT_ENCRYPTION_ALGORITHM,
      alg: LEGACY_KEY_WRAP_ALGORITHM,
      kid,
    })
    .encrypt(publicKey);
  return packBody(encryptedAESKey, encryptedPayload);
}

/** Re-encodes a compact JWE's protected header with `overrides` applied, leaving the rest intact. */
export function tamperProtectedHeader(token: string, overrides: Record<string, string>): string {
  const parts = token.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const tampered = Buffer.from(JSON.stringify({ ...header, ...overrides }), 'utf8').toString(
    'base64url'
  );
  return [tampered, ...parts.slice(1)].join('.');
}

/** Reads the protected header of a compact JWE. */
export function readProtectedHeader(token: string): Record<string, string> {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}
