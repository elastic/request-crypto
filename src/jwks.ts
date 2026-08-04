import {
  CONTENT_ALGORITHM,
  decryptContent,
  encryptCompact,
  MAX_DECOMPRESSED_SIZE,
  parseCompact,
  unwrapKey,
  ZIP_DEFLATE,
} from './jwe';
import { generateJWK, isJWKS, KeyStore, StoredKey } from './keystore';

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

// Reproduces @types/node-jose's JWK.KeyUse ('sig' | 'enc' | 'desc'), which is wider than
// this package's KeyUse. Narrowing to KeyUse would make a consumer's `use === 'sig'` check
// a TS2367 error; widening to string would break `const u: KeyUse = meta.use`.
export interface JWKMetadata {
  length: number;
  kty: string;
  kid: string;
  use: KeyUse | 'sig';
  alg: string;
}

export type KeyUse = 'enc' | 'desc';
export type PublicJWKS = JWKS<PublicJWK>;

export type PrivateJWKS = JWKS<PrivateJWK>;
export type JWK = PrivateJWK | PublicJWK;
export type UnsignedJWK = PrivateJWK | PublicJWK;

export const RSA_ALGORITHM = 'RSA-OAEP';

export interface JWKDecryptResult {
  key: JWKMetadata;
  /**
   * an object of "protected" member key values.
   */
  header: Record<string, string>;
  protected: string[];
  plaintext: Buffer;
  /**
   * payload Buffer — same Buffer object as plaintext (node-jose parity)
   */
  payload: Buffer;
}

export interface JWKSManagerOptions {
  // Cap on inflated plaintext for zip: DEF tokens. Defaults to MAX_DECOMPRESSED_SIZE (250 KB).
  // Raise it only if you hold historical tokens whose plaintext exceeds the default.
  // Must be a positive finite number.
  maxDecompressedSize?: number;
}

export class JWKSManager {
  public store: KeyStore;
  private maxDecompressedSize: number;

  constructor(store: KeyStore, options: JWKSManagerOptions = {}) {
    this.store = store;
    const specifiedSize = options.maxDecompressedSize;
    if (specifiedSize !== undefined) {
      if (!isFinite(specifiedSize) || specifiedSize <= 0) {
        throw new Error('maxDecompressedSize must be a positive finite number');
      }
      this.maxDecompressedSize = specifiedSize;
    } else {
      this.maxDecompressedSize = MAX_DECOMPRESSED_SIZE;
    }
  }

  public async addKey(
    kid: string | undefined,
    modulus: number,
    use: KeyUse,
    alg?: string
  ): Promise<void> {
    const keyAlg = alg !== undefined ? alg : RSA_ALGORITHM;
    const jwk = await generateJWK(modulus, { alg: keyAlg, use, kid });
    await this.insertKey(jwk);
  }

  public async insertKey(jwk: JWK | Buffer | string): Promise<void> {
    await this.store.add(jwk);
  }

  public getPublicJWK(kid?: string): PublicJWK | null {
    const key = this.getKey(kid);
    if (!key) {
      return null;
    }
    return key.toJSON() as PublicJWK;
  }

  public getPrivateJWK(kid?: string): PrivateJWK | null {
    const key = this.getKey(kid);
    if (!key || !key.isPrivate) {
      return null;
    }
    return key.toJSON(true) as PrivateJWK;
  }

  public getPublicJWKS(): PublicJWKS {
    return this.store.toJSON() as PublicJWKS;
  }

  public getPrivateJWKS(): PrivateJWKS {
    return this.store.toJSON(true) as PrivateJWKS;
  }

  public removeKey(key: PublicJWK | PrivateJWK): void {
    return this.store.remove(key);
  }

  public async encrypt(kid: string, input: Buffer): Promise<string> {
    const key = this.getKey(kid);
    if (!key) {
      throw Error(`Missing kid (${kid}).`);
    }
    // Header alg comes from the KEY, not from RSA_ALGORITHM. Verified against node-jose 2.2.0:
    // JWE.createEncrypt with no explicit alg emits the JWK's own alg member, falling back to
    // 'RSA-OAEP' when absent. Hardcoding RSA_ALGORITHM here would silently downgrade a JWKS
    // published as RSA-OAEP-256 and produce tokens its own receiver rejects with 'no key found'.
    // object-literal-sort-keys: false is what permits {zip, enc, alg, kid} — do not alphabetize.
    return encryptCompact(
      key.publicKey,
      { zip: ZIP_DEFLATE, enc: CONTENT_ALGORITHM, alg: key.alg || RSA_ALGORITHM, kid: key.kid },
      input
    );
  }

  public async decrypt(payload: any, jwks: KeyStore = this.store): Promise<JWKDecryptResult> {
    const parsed = parseCompact(payload);
    const header = parsed.protectedHeader;
    // Filtering by alg reproduces node-jose's mechanism: an RSA1_5 header finds no candidate
    // and yields 'no key found' rather than attempting a PKCS#1 v1.5 unwrap.
    const key = jwks.get({ kid: header.kid, use: 'enc', alg: header.alg });
    if (!key || !key.privateKey) {
      throw new Error('no key found');
    }
    const cek = unwrapKey(parsed, key.privateKey);
    const plaintext = decryptContent(parsed, cek, this.maxDecompressedSize);
    return {
      key: key.metadata(),
      header,
      protected: parsed.protectedFields,
      plaintext,
      // payload === plaintext — same Buffer object, node-jose parity
      payload: plaintext,
    };
  }

  protected getKey(kid?: string): StoredKey | null {
    return this.store.get(kid);
  }
}

export async function createJWKS(jwks?: JWKS | string | Buffer): Promise<KeyStore> {
  const store = new KeyStore();
  if (jwks === undefined) {
    return store;
  }
  let parsed: any;
  if (typeof jwks === 'string' || Buffer.isBuffer(jwks)) {
    try {
      parsed = JSON.parse(typeof jwks === 'string' ? jwks : (jwks as Buffer).toString('utf8'));
    } catch (e) {
      throw new TypeError('invalid JWKS: ' + e.message);
    }
  } else {
    parsed = jwks;
  }
  if (!isJWKS(parsed)) {
    throw new TypeError('expected a JWKS ({ keys: [...] }), got ' + typeof parsed);
  }
  for (const k of parsed.keys) {
    await store.add(k);
  }
  return store;
}

export async function createJWKSManager(jwks?: JWKS, options?: JWKSManagerOptions) {
  const store = await createJWKS(jwks);
  return new JWKSManager(store, options);
}
