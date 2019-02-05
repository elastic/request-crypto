import * as jose from 'node-jose';

export const POPKEY_MODULUS = 1024;
export type Identity = string;
export type Confirmation = string;

import {
  createJWKS,
  JWKS,
  JWKSManager,
  PrivateJWK,
  PrivateJWKS,
  PublicJWK,
  PublicJWKS,
  SignedPublicJWK,
  SignedPublicJWKS,
} from './jwks';

export class POPManager extends JWKSManager {
  public async addKey(kid?: string): Promise<void> {
    await super.addKey(kid, POPKEY_MODULUS, 'pop');
  }
  public getIdentity(kid?: string): Identity {
    const publicPopJWK = this.store.get(kid);
    return Buffer.from(JSON.stringify(publicPopJWK.toJSON()), 'utf8').toString('base64');
  }
  public parseIdentity(identity: string): PublicJWK {
    return JSON.parse(Buffer.from(identity, 'base64').toString('utf8'));
  }
  public async createSignature(
    usignedJWK: PublicJWK,
    popKey: Identity | PublicJWK
  ): Promise<Confirmation> {
    const parsedPOPKey = typeof popKey === 'string' ? this.parseIdentity(popKey) : popKey;
    parsedPOPKey.use = 'enc';
    const parsedUJWK = await this.JWK.asKey(usignedJWK, 'json');
    const ujwkFingerprint = await parsedUJWK.thumbprint();
    const encryptConfig = { format: 'compact', zip: true };
    const encrypter = this.JWE.createEncrypt(encryptConfig, parsedPOPKey);
    parsedPOPKey.use = 'pop';
    return encrypter.update(ujwkFingerprint).final();
  }
  public async signPublicJWKS(
    jwks: PublicJWKS,
    popKey: Identity | PublicJWK
  ): Promise<SignedPublicJWKS> {
    return {
      ...jwks,
      keys: await Promise.all(
        jwks.keys.map(async (key: PublicJWK) => {
          const cnf = await this.createSignature(key, popKey);
          return { ...key, cnf };
        })
      ),
    };
  }
  public isSigned(jwk: PublicJWK | SignedPublicJWK): jwk is SignedPublicJWK {
    return 'cnf' in jwk;
  }
  public async verifyJWK(signedPublicJWK: SignedPublicJWK, popJWKS: PrivateJWKS): Promise<boolean> {
    if (!this.isSigned(signedPublicJWK)) {
      return false;
    }

    const popJWKStore = await this.JWK.asKeyStore({
      ...popJWKS,
      keys: popJWKS.keys.map((jwk: PrivateJWK) => ({ ...jwk, use: 'enc' })),
    });

    const decryptedConfirmation = await this.decrypt(signedPublicJWK.cnf, popJWKStore);
    const parsedJWK = await this.JWK.asKey(signedPublicJWK, 'json');
    const ujwkFingerprint = await parsedJWK.thumbprint();

    return decryptedConfirmation.equals(ujwkFingerprint);
  }
  public async verifyJWKS(
    signedPublicJWKS: SignedPublicJWKS,
    popJWKS?: PrivateJWKS
  ): Promise<boolean> {
    const popPrivateJWKS = popJWKS || this.getPrivateJWKS();
    for (let i = 0, l = signedPublicJWKS.keys.length; i < l; i++) {
      const sJWK: SignedPublicJWK = signedPublicJWKS.keys[i];
      const isKeyVerified = await this.verifyJWK(sJWK, popPrivateJWKS);
      if (!isKeyVerified) {
        return false;
      }
    }
    return true;
  }
}

export async function createPOPManager(jwks?: JWKS, jwk = jose.JWK) {
  const store = await createJWKS(jwk, jwks);
  return new POPManager(store, jwk);
}
