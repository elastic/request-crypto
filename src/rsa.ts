import * as crypto from 'crypto';
import * as constants from 'constants';

const PUBLIC_RSA_PADDING: number = constants.RSA_PKCS1_OAEP_PADDING;
const PRIVATE_RSA_PADDING: number = constants.RSA_PKCS1_OAEP_PADDING;

type AnyRsaKey = crypto.RsaPublicKey | crypto.RsaPrivateKey;
export type PublicKey = string | crypto.RsaPublicKey;
export type PrivateKey = string | crypto.RsaPrivateKey;
export interface RsaPair {
  publicKey?: PublicKey;
  privateKey?: PrivateKey;
}

function createKeyDetails(key: PublicKey | PrivateKey | undefined, padding: number): AnyRsaKey | null {
  if (typeof key === 'undefined') {
    return null;
  }

  return {
    ...(typeof key === 'string' ? { key } : key),
    padding,
  };
}

export function makeRSACryptoWith(pair: RsaPair) {
  const privateKey = createKeyDetails(pair.privateKey, PRIVATE_RSA_PADDING);
  const publicKey = createKeyDetails(pair.publicKey, PUBLIC_RSA_PADDING);

  function publicEncrypt(message: string): Buffer {
    if (!publicKey) {
      throw Error('Public Key required.');
    }
    const messageBuffer = Buffer.from(message, 'utf-8');
    return crypto.publicEncrypt(publicKey, messageBuffer);
  }

  function publicDecrypt(message: string): Buffer {
    if (!publicKey) {
      throw Error('Public Key required.');
    }
    const messageBuffer = Buffer.from(message, 'base64');

    return crypto.publicDecrypt(publicKey, messageBuffer);
  }

  function privateDecrypt(message: string): Buffer {
    if (!privateKey) {
      throw Error('Private Key required.');
    }
    const messageBuffer = Buffer.from(message, 'base64');

    return crypto.privateDecrypt(privateKey, messageBuffer);
  }

  function privateEncrypt(message: string): Buffer {
    if (!privateKey) {
      throw Error('Private Key required.');
    }
    const messageBuffer = Buffer.from(message, 'base64');

    return crypto.privateEncrypt(privateKey, messageBuffer);
  }

  return {
    publicEncrypt,
    publicDecrypt,
    privateEncrypt,
    privateDecrypt,
  };
}
