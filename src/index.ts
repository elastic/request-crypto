import { makeAESCryptoWith } from './aes';
import { generatePassphrase } from './generate-rsa';
import { makeRSACryptoWith, PrivateKey, PublicKey } from './rsa';

export async function encryptPayload(payload: Partial<object>, publicKey: PublicKey) {
  const AESKey = generatePassphrase();
  const AES = makeAESCryptoWith({ encryptionKey: AESKey });
  const encryptedPayload = await AES.encrypt(payload);

  const RSA = makeRSACryptoWith({ publicKey });
  const encryptedKey = RSA.publicEncrypt(AESKey);

  return {
    payload: encryptedPayload,
    key: encryptedKey.toString('base64'),
  };
}

export async function decryptPayload(payload: string, encryptedAESKey: string, privateKey: PrivateKey) {
  const RSA = makeRSACryptoWith({ privateKey });
  const AESKey = RSA.privateDecrypt(encryptedAESKey);

  const AES = makeAESCryptoWith({ encryptionKey: AESKey });
  return AES.decrypt(payload);
}
