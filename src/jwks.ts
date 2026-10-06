import {
  calculateJwkThumbprint,
  compactDecrypt,
  CompactEncrypt,
  CompactJWEHeaderParameters,
  CryptoKey,
  exportJWK,
  generateKeyPair,
  importJWK,
} from 'jose';

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

export interface JWKMetadata {
  length: number;
  kty: string;
  kid: string;
  use: string;
  alg: string;
}

export type KeyUse = 'enc' | 'desc';
export type PublicJWKS = JWKS<PublicJWK>;
export type PrivateJWKS = JWKS<PrivateJWK>;
export type JWK = PrivateJWK | PublicJWK;
export type UnsignedJWK = PrivateJWK | PublicJWK;

/**
 * Key wrap algorithm used for every token this library produces: "RSA-OAEP-256" — RSAES-OAEP with
 * SHA-256 and MGF1-SHA-256. Encryption uses this and nothing else, because the legacy alternative
 * below is built on SHA-1, which is not a FIPS 140-3 approved hash.
 */
export const KEY_WRAP_ALGORITHM = 'RSA-OAEP-256';

/**
 * Legacy key wrap algorithm: "RSA-OAEP" — RSAES-OAEP with SHA-1 and MGF1-SHA-1. Accepted when
 * decrypting, never emitted when encrypting. See docs/rsa-oaep-256-migration.md.
 */
export const LEGACY_KEY_WRAP_ALGORITHM = 'RSA-OAEP';

/**
 * Key wrap algorithms accepted when decrypting. Every token names its own key wrap algorithm in its
 * protected "alg" header, so the receiver does not negotiate or guess — it reads the header and
 * uses the matching key binding. This list is the allowlist handed to jose, so an unexpected "alg"
 * is rejected before any key is resolved, and it is the single place to edit when legacy support is
 * eventually dropped.
 */
export const SUPPORTED_KEY_WRAP_ALGORITHMS = [KEY_WRAP_ALGORITHM, LEGACY_KEY_WRAP_ALGORITHM];

/** Content encryption algorithm: AES-128-CBC with an HMAC-SHA-256 tag. Pinned on both sides. */
export const CONTENT_ENCRYPTION_ALGORITHM = 'A128CBC-HS256';

/**
 * Ceiling on the inflated size of a `zip: "DEF"` JWE plaintext, so a small token cannot expand
 * without bound on decompression. Requests carry a 32-byte AES passphrase in the JWE, so this is
 * several orders of magnitude above anything legitimate; it matches jose's own default.
 */
export const MAX_DECOMPRESSED_LENGTH = 250000;

/**
 * @deprecated Prefer `KEY_WRAP_ALGORITHM` (what this library encrypts with) or
 * `LEGACY_KEY_WRAP_ALGORITHM` (what it additionally accepts when decrypting). Retained as an alias
 * of the legacy algorithm so existing imports keep resolving.
 */
export const RSA_ALGORITHM = LEGACY_KEY_WRAP_ALGORITHM;

export interface JWKDecryptResult {
  /**
   * JWK metadata
   */
  key: JWKMetadata;
  /**
   * an object of "protected" member key values.
   */
  header: Record<string, string>;
  /**
   * array of protected member names
   */
  protected: string[];
  /**
   * plaintext Buffer (alias of payload for back-compat)
   */
  plaintext: Buffer;
  /**
   * payload Buffer
   */
  payload: Buffer;
}

export interface KeyEntry {
  kid: string;
  use: KeyUse;
  alg: string;
  publicJwk: PublicJWK;
  privateJwk?: PrivateJWK;
}

type KeyKind = 'public' | 'private';

/**
 * Imported CryptoKeys, cached per key entry and per key wrap algorithm.
 *
 * WebCrypto binds an RSA-OAEP key to exactly one hash when it is imported, and jose enforces that
 * the binding matches the token's "alg" header — a key imported for "RSA-OAEP" (SHA-1) throws
 * `CryptoKey does not support this operation, its algorithm.hash must be SHA-256` if handed an
 * "RSA-OAEP-256" token, and vice versa. One CryptoKey therefore cannot serve both algorithms, so
 * each entry keeps one import per algorithm it has actually been asked for.
 */
const importedKeys = new WeakMap<KeyEntry, Map<string, Promise<CryptoKey>>>();

function getImportCache(entry: KeyEntry): Map<string, Promise<CryptoKey>> {
  let cache = importedKeys.get(entry);
  if (cache == null) {
    cache = new Map();
    importedKeys.set(entry, cache);
  }
  return cache;
}

/**
 * Imports a key for one specific key wrap algorithm.
 *
 * The `alg` argument deliberately overrides the JWK's own "alg" member: every key this library has
 * ever generated — including the public keys shipped with Kibana — is stamped `alg: "RSA-OAEP"`,
 * yet those same keys must now wrap with "RSA-OAEP-256". Passing "alg" explicitly also means a JWK
 * that omits the member entirely still imports, which is not true of the JWK's own value.
 */
async function importKeyForAlg(
  entry: KeyEntry,
  jwk: JWK,
  alg: string,
  kind: KeyKind
): Promise<CryptoKey> {
  const cache = getImportCache(entry);
  const cacheKey = `${kind}:${alg}`;
  const cached = cache.get(cacheKey);
  if (cached != null) {
    return cached;
  }
  // Cast to jose's JWK union; our PublicJWK/PrivateJWK are structurally compatible for import.
  const pending = (importJWK(jwk as Parameters<typeof importJWK>[0], alg, {
    // Private keys stay extractable so getPrivateJWKS() can round-trip them.
    extractable: true,
  }) as Promise<CryptoKey>).catch(err => {
    // Never cache a failure: a malformed JWK should raise the same error on every attempt.
    cache.delete(cacheKey);
    throw err;
  });
  cache.set(cacheKey, pending);
  return pending;
}

function getPublicKeyForAlg(entry: KeyEntry, alg: string): Promise<CryptoKey> {
  return importKeyForAlg(entry, entry.publicJwk, alg, 'public');
}

function getPrivateKeyForAlg(
  entry: KeyEntry,
  privateJwk: PrivateJWK,
  alg: string
): Promise<CryptoKey> {
  return importKeyForAlg(entry, privateJwk, alg, 'private');
}

// tslint:disable-next-line: max-classes-per-file
export class KeyStore {
  private entries: KeyEntry[] = [];

  public async add(entry: KeyEntry): Promise<void> {
    this.entries.push(entry);
  }

  public get(kid?: string): KeyEntry | undefined {
    if (kid !== undefined) {
      return this.entries.find(e => e.kid === kid);
    }
    return this.entries[0];
  }

  public remove(jwk: PublicJWK | PrivateJWK): void {
    this.entries = this.entries.filter(e => e.kid !== jwk.kid);
  }

  public toJSON(): PublicJWKS;
  public toJSON(includePrivate: true): PrivateJWKS;
  public toJSON(includePrivate = false): PublicJWKS | PrivateJWKS {
    if (includePrivate) {
      return {
        keys: this.entries.map(
          e => (e.privateJwk != null ? e.privateJwk : e.publicJwk) as PrivateJWK
        ),
      };
    }
    return { keys: this.entries.map(e => e.publicJwk) };
  }
}

// tslint:disable-next-line: max-classes-per-file
export class JWKSManager {
  public store: KeyStore;

  constructor(store: KeyStore) {
    this.store = store;
  }

  public async addKey(kid: string | undefined, modulus: number, use: KeyUse): Promise<void> {
    const { privateKey, publicKey } = await generateKeyPair(KEY_WRAP_ALGORITHM, {
      modulusLength: modulus,
      extractable: true,
    });
    const [privateJwkRaw, publicJwkRaw] = await Promise.all([
      exportJWK(privateKey as CryptoKey),
      exportJWK(publicKey as CryptoKey),
    ]);
    // node-jose generated a kid when the caller did not supply one. Falling back to an empty string
    // instead would let two unnamed keys collide on the same entry, so derive an RFC 7638 (SHA-256)
    // thumbprint: deterministic, so the same key material always yields the same identifier.
    const resolvedKid = kid != null ? kid : await calculateJwkThumbprint(publicJwkRaw);
    const publicJwk: PublicJWK = {
      kty: publicJwkRaw.kty!,
      kid: resolvedKid,
      use,
      alg: KEY_WRAP_ALGORITHM,
      e: publicJwkRaw.e!,
      n: publicJwkRaw.n!,
    };
    const privateJwk: PrivateJWK = {
      ...publicJwk,
      d: privateJwkRaw.d!,
      p: privateJwkRaw.p!,
      q: privateJwkRaw.q!,
      dp: privateJwkRaw.dp!,
      dq: privateJwkRaw.dq!,
      qi: privateJwkRaw.qi!,
    };
    await this.insertKey({
      kid: resolvedKid,
      use,
      alg: KEY_WRAP_ALGORITHM,
      publicJwk,
      privateJwk,
    });
  }

  public async insertKey(entry: KeyEntry): Promise<void> {
    await this.store.add(entry);
  }

  public getPublicJWK(kid?: string): PublicJWK | null {
    const entry = this.store.get(kid);
    return entry != null ? entry.publicJwk : null;
  }

  public getPrivateJWK(kid?: string): PrivateJWK | null {
    const entry = this.store.get(kid);
    return entry != null && entry.privateJwk != null ? entry.privateJwk : null;
  }

  public getPublicJWKS(): PublicJWKS {
    return this.store.toJSON();
  }

  public getPrivateJWKS(): PrivateJWKS {
    return this.store.toJSON(true);
  }

  public removeKey(key: PublicJWK | PrivateJWK): void {
    this.store.remove(key);
  }

  /**
   * Encrypts with `KEY_WRAP_ALGORITHM` ("RSA-OAEP-256") only. The key's own JWK "alg" member is
   * ignored, so keys stamped with the legacy algorithm — which is all of them in production — still
   * produce SHA-256 tokens without the key having to be rotated or re-published first.
   */
  public async encrypt(kid: string, input: Buffer): Promise<string> {
    const entry = this.store.get(kid);
    if (!entry) {
      throw new Error(`Missing kid (${kid}).`);
    }
    const publicKey = await getPublicKeyForAlg(entry, KEY_WRAP_ALGORITHM);
    // Header key order matches node-jose's: zip, enc, alg, kid — preserving the wire format.
    return new CompactEncrypt(Uint8Array.from(input))
      .setProtectedHeader({
        zip: 'DEF',
        enc: CONTENT_ENCRYPTION_ALGORITHM,
        alg: KEY_WRAP_ALGORITHM,
        kid,
      })
      .encrypt(publicKey);
  }

  /**
   * Decrypts a compact JWE, accepting either key wrap algorithm.
   *
   * Key wrap is deliberately asymmetric: encryption emits "RSA-OAEP-256" exclusively, while
   * decryption accepts both "RSA-OAEP-256" and the legacy "RSA-OAEP" (RSAES-OAEP, SHA-1 +
   * MGF1-SHA-1). The algorithm is not negotiated or guessed — every JWE names it in its protected
   * "alg" header, jose checks that value against `SUPPORTED_KEY_WRAP_ALGORITHMS` before any key is
   * touched, and the resolver below then imports the key binding that matches.
   *
   * The asymmetry is what makes the migration safe to roll out. Receivers cannot switch in lockstep
   * with senders, and a receiver running request-crypto 2.x (node-jose) cannot decrypt
   * "RSA-OAEP-256" at all: node-jose intersects a key's usable algorithms with the JWK's own "alg"
   * member (`JWK.Key#algorithms()`) and `unwrap()` rejects anything outside that list, so a key
   * stamped `alg: "RSA-OAEP"` refuses SHA-256 tokens outright. Receivers therefore upgrade first and
   * sit on mixed traffic; senders switch afterwards, at their own pace. Legacy tokens are accepted
   * for as long as any un-upgraded sender exists — see docs/rsa-oaep-256-migration.md.
   */
  public async decrypt(payload: string, store = this.store): Promise<JWKDecryptResult> {
    const keyResolver = async (header: CompactJWEHeaderParameters) => {
      const keyEntry = store.get(header.kid);
      if (!keyEntry || !keyEntry.privateJwk) {
        throw new Error('no key found');
      }
      // header.alg is guaranteed to be one of SUPPORTED_KEY_WRAP_ALGORITHMS: jose validates it
      // against the allowlist below before invoking this resolver.
      return getPrivateKeyForAlg(keyEntry, keyEntry.privateJwk, header.alg!);
    };
    const { plaintext, protectedHeader } = await compactDecrypt(payload, keyResolver, {
      keyManagementAlgorithms: SUPPORTED_KEY_WRAP_ALGORITHMS,
      contentEncryptionAlgorithms: [CONTENT_ENCRYPTION_ALGORITHM],
      maxDecompressedLength: MAX_DECOMPRESSED_LENGTH,
    });
    const entry = store.get((protectedHeader as CompactJWEHeaderParameters).kid);
    const payloadBuffer = Buffer.from(plaintext);
    const publicJwk = entry!.publicJwk;
    return {
      payload: payloadBuffer,
      plaintext: payloadBuffer,
      header: (protectedHeader as unknown) as Record<string, string>,
      protected: Object.keys(protectedHeader),
      key: {
        length: Buffer.from(publicJwk.n, 'base64url').length * 8,
        kty: publicJwk.kty,
        kid: publicJwk.kid,
        use: publicJwk.use,
        alg: publicJwk.alg,
      },
    };
  }

  protected getKey(kid?: string): KeyEntry | undefined {
    return this.store.get(kid);
  }
}

export async function createJWKS(jwks?: JWKS): Promise<KeyStore> {
  const store = new KeyStore();
  if (!jwks) {
    return store;
  }
  for (const key of jwks.keys) {
    const isPrivate = 'd' in key;
    const publicJwk: PublicJWK = {
      kty: key.kty,
      kid: key.kid,
      use: key.use as KeyUse,
      alg: key.alg,
      e: (key as PublicJWK).e,
      n: (key as PublicJWK).n,
    };
    const entry: KeyEntry = {
      kid: key.kid,
      use: key.use as KeyUse,
      alg: key.alg,
      publicJwk,
    };
    if (isPrivate) {
      entry.privateJwk = key as PrivateJWK;
    }
    // Import eagerly for the algorithm this library encrypts and expects to decrypt with, so a
    // malformed JWK fails here rather than on first use. The legacy binding is imported lazily,
    // only if a legacy token actually arrives.
    await getPublicKeyForAlg(entry, KEY_WRAP_ALGORITHM);
    if (entry.privateJwk != null) {
      await getPrivateKeyForAlg(entry, entry.privateJwk, KEY_WRAP_ALGORITHM);
    }
    await store.add(entry);
  }
  return store;
}

export async function createJWKSManager(jwks?: JWKS): Promise<JWKSManager> {
  const store = await createJWKS(jwks);
  return new JWKSManager(store);
}
