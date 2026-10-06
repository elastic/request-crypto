import _makeAESCryptoWith, { Crypto, CryptoOptions, EncryptOutput } from '@elastic/node-crypto';

import { createJWKManager } from './jwk.js';
import {
  JWKDecryptResult,
  LEGACY_KEY_WRAP_ALGORITHM,
  PrivateJWKS,
  PublicJWK,
  PublicJWKS,
} from './jwks.js';
import { generatePassphrase } from './random-bytes.js';

// @elastic/node-crypto is a CJS module. Under Node.js ESM, importing a CJS default always
// yields the full exports object, not just the .default property. Unwrap it explicitly.
const makeAESCryptoWith: (opts: CryptoOptions) => Crypto =
  (_makeAESCryptoWith as any).default || _makeAESCryptoWith;

export interface Encryptor {
  encrypt(kid: string, input: any): Promise<string>;
}

export interface Decryptor {
  getPublicComponent(kid: string): PublicJWK | null;
  getWellKnowns(): PublicJWKS;
  decrypt(encryptedBody: string): Promise<EncryptOutput | EncryptOutput[]>;
  getJWKMetadata(
    encryptedBody: string
  ): Promise<Pick<JWKDecryptResult, 'key' | 'protected' | 'header'>>;
}

/** The key wrap algorithm a decrypted request actually used. */
export interface KeyWrapInfo {
  /** The "kid" from the token's protected header, when it carried one. */
  kid?: string;
  /** The "alg" from the token's protected header: "RSA-OAEP-256" or the legacy "RSA-OAEP". */
  alg: string;
  /** True when the sender used the legacy SHA-1 based "RSA-OAEP" key wrap. */
  legacy: boolean;
}

export interface DecryptorOptions {
  /**
   * Called once a request has been fully decrypted, with the key wrap algorithm its token used.
   * Receivers can wire this to a counter to watch legacy "RSA-OAEP" traffic drain away as senders
   * upgrade - that measurement is what tells you when legacy support can safely be dropped, and
   * when the receiver can run under a FIPS-only crypto provider. It fires for both algorithms so
   * the ratio is available, not just the legacy count.
   *
   * It fires only after the payload authenticates, so the count reconciles with the requests the
   * service actually served. A request whose payload fails to decrypt is not counted; call
   * `getJWKMetadata` on that body to recover the algorithm it used.
   *
   * A throw or a rejected promise from this callback is swallowed, so instrumentation can never
   * fail a request. See docs/rsa-oaep-256-migration.md.
   */
  onKeyWrap?(info: KeyWrapInfo): void | Promise<void>;
}

export async function createRequestEncryptor(publicJWKS: PublicJWKS): Promise<Encryptor> {
  const jwkManager = await createJWKManager(publicJWKS);
  return {
    async encrypt(kid, input) {
      const AESKeyBuffer = generatePassphrase();
      const AES = makeAESCryptoWith({ encryptionKey: AESKeyBuffer });
      const encryptedPayload = await AES.encrypt(input);
      const encryptedKey = await jwkManager.encrypt(kid, AESKeyBuffer);
      return packBody(encryptedKey, encryptedPayload);
    },
  };
}

export async function createRequestDecryptor(
  privateJWKS: PrivateJWKS,
  options: DecryptorOptions = {}
): Promise<Decryptor> {
  const jwkManager = await createJWKManager(privateJWKS);
  const notifyKeyWrap = (header: Record<string, string>) => {
    if (options.onKeyWrap == null) {
      return;
    }
    try {
      const result = options.onKeyWrap({
        kid: header.kid,
        alg: header.alg,
        legacy: header.alg === LEGACY_KEY_WRAP_ALGORITHM,
      });
      // Attach the rejection handler before returning. An async hook's promise otherwise becomes
      // an unhandled rejection, which Node reports as an uncaught exception.
      Promise.resolve(result).catch(() => {
        // Instrumentation must never break decryption.
      });
    } catch (err) {
      // Instrumentation must never break decryption.
    }
  };
  return {
    getPublicComponent(kid: string) {
      return jwkManager.getPublicJWK(kid);
    },
    getWellKnowns() {
      return jwkManager.getPublicJWKS();
    },
    async decrypt(encryptedBody: string) {
      const { encryptedAESKey, encryptedPayload } = unpackBody(encryptedBody);
      const { payload: encryptionKeyBuffer, header } = await jwkManager.decrypt(encryptedAESKey);
      const AES = makeAESCryptoWith({ encryptionKey: encryptionKeyBuffer });
      // Notify only once the payload authenticates. Unwrapping the AES key proves the sender's key
      // wrap, but the request is not served until this resolves, and the counter is read as served
      // traffic. getJWKMetadata recovers the algorithm for a body that fails here.
      const payload = await AES.decrypt(encryptedPayload);
      notifyKeyWrap(header);
      return payload;
    },
    async getJWKMetadata(encryptedBody: string) {
      const { encryptedAESKey } = unpackBody(encryptedBody);
      const { key, protected: protectedFields, header } = await jwkManager.decrypt(encryptedAESKey);
      notifyKeyWrap(header);
      return { key, protected: protectedFields, header };
    },
  };
}

export function packBody(encryptedAESKey: string, encryptedPayload: string): string {
  const packedBodyStringifiedJSON = JSON.stringify({
    encryptedAESKey,
    encryptedPayload,
  });
  return Buffer.from(packedBodyStringifiedJSON, 'utf8').toString('base64url');
}

export function unpackBody(packedBody: string) {
  const decodedBody = Buffer.from(packedBody, 'base64url');
  const { encryptedAESKey, encryptedPayload } = JSON.parse(decodedBody.toString('utf8'));
  return { encryptedAESKey, encryptedPayload };
}
