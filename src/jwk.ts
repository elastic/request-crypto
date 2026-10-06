import { createJWKS, JWKS, JWKSManager, KeyStore } from './jwks.js';

export const ENC_MODULUS = 2048;

export class JWKManager extends JWKSManager {
  /**
   * Adds a freshly generated 2048-bit encryption key. When `kid` is omitted, one is derived from
   * the key's RFC 7638 thumbprint rather than left empty.
   */
  public addKey(kid?: string) {
    return super.addKey(kid, ENC_MODULUS, 'enc');
  }
}

export async function createJWKManager(jwks?: JWKS): Promise<JWKManager> {
  const store: KeyStore = await createJWKS(jwks);
  return new JWKManager(store);
}
