import { makeAESCryptoWith } from './aes';
import { createJWKManager } from './jwk';
import { PrivateJWKS, PublicJWK, PublicJWKS } from './jwks';
import { generatePassphrase } from './random-bytes';

export interface EncryptionOutput {
  key: string;
  payload: string;
}

export interface Encryptor {
  encrypt(kid: string, input: any): Promise<EncryptionOutput>;
}

export interface Decryptor {
  getPublicComponent(kid: string): PublicJWK;
  getWellKnowns(): PublicJWKS;
  decrypt(payload: string, encryptedAESKey: string): Promise<Buffer>;
}

export async function createRequestEncryptor(publicJWKS: PublicJWKS): Promise<Encryptor> {
  const jwkManager = await createJWKManager(publicJWKS);
  return {
    async encrypt(kid, input) {
      const AESKey = generatePassphrase();
      const AES = makeAESCryptoWith({ encryptionKey: AESKey });
      const encryptedPayload = await AES.encrypt(input);

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
    getPublicComponent(kid) {
      return jwkManager.getPublicJWK(kid);
    },
    getWellKnowns() {
      return jwkManager.getPublicJWKS();
    },
    async decrypt(payload, encryptedAESKey) {
      const encryptionKeyBuffer = await jwkManager.decrypt(encryptedAESKey);
      const encryptionKey = encryptionKeyBuffer.toString('base64');

      const AES = makeAESCryptoWith({ encryptionKey });
      return AES.decrypt(payload);
    },
  };
}
