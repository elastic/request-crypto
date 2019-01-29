import * as jose from 'node-jose';

interface JWKS<T = PublicJWK | FullJWK> {
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

export interface FullJWK extends PublicJWK {
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

export type KeyUse = 'sig' | 'enc' | 'desc';
export type PublicJWKS = JWKS<PublicJWK>;
export type FullJWKS = JWKS<FullJWK>;

export const MODULUS = 4096;
export const RSA_ALGORITHM = 'RSA-OAEP';

async function createJWKS(JWK: jose.JWK, jwks?: JWKS) {
  const storeMethod = jwks && jwks.keys.length ? 'asKeyStore' : 'createKeyStore';
  return JWK[storeMethod](jwks);
}

export async function createJWKManager(jwks?: JWKS) {
  const keySet = await createJWKS(createJWKManager.JWK, jwks);

  return {
    JWK: createJWKManager.JWK,
    JWE: createJWKManager.JWE,
    getPublicJWKS(): PublicJWKS {
      return keySet.toJSON();
    },
    getFullJWKS(): FullJWKS {
      return keySet.toJSON(true);
    },
    async addKey(kid: string, use: KeyUse = 'enc'): Promise<FullJWK> {
      const rsaKey = await this.JWK.createKey('RSA', MODULUS, {
        alg: RSA_ALGORITHM,
        use,
        kid,
      });
      return keySet.add(rsaKey);
    },
    getKey(kid: string) {
      return keySet.get(kid);
    },
    async encrypt(kid: string, payload: string | Buffer): Promise<string> {
      const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'base64');

      const effectiveKey = this.getKey(kid);
      const encryptConfig = {
        format: 'compact',
        zip: true,
      };
      const encrypter = this.JWE.createEncrypt(encryptConfig, effectiveKey);

      return encrypter.update(payloadBuffer).final();
    },
    async decrypt(payload: any, encoding = 'base64') {
      const decrypter = this.JWE.createDecrypt(keySet);
      const decryptedPayload = await decrypter.decrypt(payload);

      return decryptedPayload.payload.toString('base64');
    },
  };
}

createJWKManager.JWK = jose.JWK;
createJWKManager.JWE = jose.JWE;
