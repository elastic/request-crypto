import * as jose from 'node-jose';

export const ENC_MODULUS = 4096;

import { createJWKS, JWKS, JWKSManager } from './jwks';

export class JWKManager extends JWKSManager {
  public addKey(kid: string) {
    return super.addKey(kid, ENC_MODULUS, 'enc');
  }
}

export async function createJWKManager(jwks?: JWKS, jwk = jose.JWK) {
  const store = await createJWKS(jwk, jwks);
  return new JWKManager(store, jwk);
}
