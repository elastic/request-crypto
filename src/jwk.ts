import { createJWKS, JWKS, JWKSManager, JWKSManagerOptions } from './jwks';

export const ENC_MODULUS = 2048;

export class JWKManager extends JWKSManager {
  public addKey(kid: string) {
    return super.addKey(kid, ENC_MODULUS, 'enc');
  }
}

export async function createJWKManager(jwks?: JWKS, options?: JWKSManagerOptions) {
  const store = await createJWKS(jwks);
  return new JWKManager(store, options);
}
