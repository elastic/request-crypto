import { makeAESCryptoWith } from './aes';
import { createJWKManager, FullJWKS, PublicJWKS } from './jwk';
import { generatePassphrase } from './random-bytes';

export * from './jwk';

export async function encryptPayload(
  payload: Partial<object>,
  kid: string,
  publicJWKS: PublicJWKS
) {
  const AESKey = generatePassphrase();
  const AES = makeAESCryptoWith({ encryptionKey: AESKey });
  const encryptedPayload = await AES.encrypt(payload);

  const jwkManager = await createJWKManager(publicJWKS);

  const AESKeyBuffer = Buffer.from(AESKey, 'base64');

  const encryptedKey = await jwkManager.encrypt(kid, AESKeyBuffer);

  return {
    payload: encryptedPayload,
    key: encryptedKey,
  };
}

export async function decryptPayload(payload: string, encryptedAESKey: string, fullJWKS: FullJWKS) {
  const jwkManager = await createJWKManager(fullJWKS);
  const encryptionKey = await jwkManager.decrypt(encryptedAESKey);

  const AES = makeAESCryptoWith({ encryptionKey });
  return AES.decrypt(payload);
}
