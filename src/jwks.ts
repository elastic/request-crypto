import * as jose from 'node-jose';

export interface JWKS<T = PublicJWK | PrivateJWK> {
  keys: T[];
}

export interface PublicJWK {
  // kty: is the key type
  kty: string;
  // kid: is the unique identifier for the key
  kid: string;
  // use: is how the key was meant to be used.
  use: KeyUse;
  // alg: is the algorithm for the key
  alg: string;
  // e: public exponent
  e: string;
  // n: is the modulus for the public component
  n: string;
}

export interface PrivateJWK extends PublicJWK {
  // d: private component
  d: string;
  // q: prime 1
  p: string;
  // q: prime 2
  q: string;
  // dp: exponent1
  dp: string;
  // dq: exponent2
  dq: string;
  // qi: coefficient
  qi: string;
}

export type JWKMetadata = Pick<jose.JWK.Key, 'length' | 'kty' | 'kid' | 'use' | 'alg'>;

export type KeyUse = 'enc' | 'desc';
export type PublicJWKS = JWKS<PublicJWK>;

export type PrivateJWKS = JWKS<PrivateJWK>;
export type JWK = PrivateJWK | PublicJWK;
export type UnsignedJWK = PrivateJWK | PublicJWK;

export const RSA_ALGORITHM = 'RSA-OAEP';

export interface JWKDecryptResult extends jose.JWE.DecryptResult {
  /**
   * JWK metadata
   */
  key: JWKMetadata;
  /**
   * an object of "protected" member key values.
   */
  header: Record<string, string>;
  /**
   * payload Buffer
   */
  payload: Buffer;
}

export class JWKSManager {
  public store: any;
  public JWK: typeof jose.JWK;
  public JWE: typeof jose.JWE;
  constructor(store: any, jwk = jose.JWK, jwe = jose.JWE) {
    this.store = store;
    this.JWK = jwk;
    this.JWE = jwe;
  }
  public async addKey(kid: string | undefined, modulus: number, use: KeyUse): Promise<void> {
    const keyConfig = { alg: RSA_ALGORITHM, use, kid };
    const privateKey = await this.JWK.createKey('RSA', modulus, keyConfig);
    await this.insertKey(privateKey);
  }
  public async insertKey(jwk: jose.JWK.Key): Promise<void> {
    await this.store.add(jwk);
  }
  public getPublicJWK(kid?: string): PublicJWK | null {
    const jwk = this.getKey(kid);
    if (!jwk) {
      return null;
    }
    return jwk.toJSON();
  }
  public getPrivateJWK(kid?: string): PrivateJWK | null {
    const jwk = this.getKey(kid);
    if (!jwk) {
      return null;
    }
    return jwk.toJSON(true);
  }
  public getPublicJWKS(): PublicJWKS {
    return this.store.toJSON();
  }
  public getPrivateJWKS(): PrivateJWKS {
    return this.store.toJSON(true);
  }
  public removeKey(key: PublicJWK | PrivateJWK): void {
    return this.store.remove(key);
  }
  public async encrypt(kid: string, input: Buffer): Promise<string> {
    const publicJWK = this.getKey(kid);
    if (!publicJWK) {
      throw Error(`Missing kid (${kid}).`);
    }

    return this.JWE.createEncrypt({ format: 'compact', zip: true }, publicJWK)
      .update(input)
      .final();
  }
  public async decrypt(payload: any, jwks = this.store): Promise<JWKDecryptResult> {
    const decrypter = this.JWE.createDecrypt(jwks);
    const decryptedPayload = (await decrypter.decrypt(payload)) as JWKDecryptResult;
    return decryptedPayload;
  }

  protected getKey(kid?: string): any {
    return this.store.get(kid);
  }
}

export async function createJWKS(jwk: typeof jose.JWK, jwks?: JWKS): Promise<any> {
  if (jwks) {
    return jwk.asKeyStore(jwks);
  }
  return jwk.createKeyStore();
}

export async function createJWKSManager(jwks?: JWKS) {
  const store = await createJWKS(jose.JWK, jwks);
  return new JWKSManager(store, jose.JWK);
}
