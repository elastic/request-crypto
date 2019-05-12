import * as jose from 'node-jose';
import { createJWKS, JWKS, JWKSManager } from './jwks';

export const ENC_MODULUS = 2048;

export class JWKManager extends JWKSManager {
  public addKey(kid: string) {
    return super.addKey(kid, ENC_MODULUS, 'enc');
  }
}

export async function createJWKManager(jwks?: JWKS, jwk = jose.JWK) {
  const store = await createJWKS(jwk, jwks);
  return new JWKManager(store, jwk);
}
