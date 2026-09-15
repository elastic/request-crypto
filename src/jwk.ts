import { createJWKS, JWKS, JWKSManager, KeyStore } from './jwks';

export const ENC_MODULUS = 2048;

export class JWKManager extends JWKSManager {
  private readonly modulusLength: number;

  constructor(store: KeyStore, options?: { modulusLength?: number }) {
    super(store);
    this.modulusLength =
      options != null && options.modulusLength != null ? options.modulusLength : ENC_MODULUS;
  }

  public addKey(kid: string) {
    return super.addKey(kid, this.modulusLength, 'enc');
  }
}

export async function createJWKManager(jwks?: JWKS, options?: { modulusLength?: number }) {
  const store = await createJWKS(jwks);
  return new JWKManager(store, options);
}
