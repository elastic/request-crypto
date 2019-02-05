import { makeAESCryptoWith } from './aes';
import { createJWKManager } from './jwk';
import { PrivateJWKS, SignedPublicJWKS } from './jwks';
import { createPOPManager, Identity } from './pop';
import { generatePassphrase } from './random-bytes';

export interface EncryptionOutput {
  key: string;
  payload: string;
}
export interface Encryptor {
  addPOPJWK(): Promise<void>;
  getPrivatePOPJWKS(): PrivateJWKS;
  getIdentity(): Identity;
  verifyAndEncrypt(
    input: any,
    kid: string,
    signedWellKnowns: SignedPublicJWKS
  ): Promise<EncryptionOutput>;
}

export interface Decryptor {
  getWellKnowns(identity: Identity): Promise<SignedPublicJWKS>;
  decryptPayload(payload: string, encryptedAESKey: string): Promise<Buffer>;
}

export async function createRequestEncryptor(privatePOPJWKS?: PrivateJWKS): Promise<Encryptor> {
  // const jwkManager = await createJWKManager();
  const popManager = await createPOPManager(privatePOPJWKS);
  return {
    async addPOPJWK() {
      await popManager.addKey();
    },
    getPrivatePOPJWKS() {
      return popManager.getPrivateJWKS();
    },
    getIdentity() {
      return popManager.getIdentity();
    },
    async verifyAndEncrypt(input, kid, signedWellKnowns) {
      const verified = await popManager.verifyJWKS(signedWellKnowns);
      if (!verified) {
        throw new Error('Invalid Confirmation Signature.');
      }

      const AESKey = generatePassphrase();
      const AES = makeAESCryptoWith({ encryptionKey: AESKey });
      const encryptedPayload = await AES.encrypt(input);

      const jwkManager = await createJWKManager(signedWellKnowns);

      const AESKeyBuffer = Buffer.from(AESKey, 'base64');

      const encryptedKey = await jwkManager.encrypt(kid, AESKeyBuffer);

      return {
        payload: encryptedPayload,
        key: encryptedKey,
      };
    },
  };
}

export async function createRequestDecryptor(privateJWKS: PrivateJWKS): Promise<Decryptor> {
  const jwkManager = await createJWKManager(privateJWKS);
  return {
    async getWellKnowns(identity) {
      const wellKnowns = jwkManager.getPublicJWKS();
      const popManager = await createPOPManager();

      return popManager.signPublicJWKS(wellKnowns, identity);
    },
    async decryptPayload(payload, encryptedAESKey) {
      const encryptionKeyBuffer = await jwkManager.decrypt(encryptedAESKey);
      const encryptionKey = encryptionKeyBuffer.toString('base64');

      const AES = makeAESCryptoWith({ encryptionKey });
      return AES.decrypt(payload);
    },
  };
}
