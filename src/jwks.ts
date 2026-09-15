import {
  compactDecrypt,
  CompactEncrypt,
  exportJWK,
  generateKeyPair,
  importJWK,
  JWEHeaderParameters,
  KeyLike,
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

export const RSA_ALGORITHM = 'RSA-OAEP';
const RSA_ENC = 'A128CBC-HS256';

export interface JWKDecryptResult {
  key: JWKMetadata;
  header: Record<string, string>;
  protected: string[];
  plaintext: Buffer;
  payload: Buffer;
}

interface KeyEntry {
  kid: string;
  use: KeyUse;
  alg: string;
  privateKey?: KeyLike;
  publicKey: KeyLike;
  publicJwk: PublicJWK;
  privateJwk?: PrivateJWK;
}

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

export class JWKSManager {
  public store: KeyStore;

  constructor(store: KeyStore) {
    this.store = store;
  }

  public async addKey(kid: string | undefined, modulusLength: number, use: KeyUse): Promise<void> {
    const { privateKey, publicKey } = await generateKeyPair(RSA_ALGORITHM, {
      modulusLength,
      extractable: true,
    });
    const [privateJwkRaw, publicJwkRaw] = await Promise.all([
      exportJWK(privateKey),
      exportJWK(publicKey),
    ]);
    const resolvedKid = kid != null ? kid : '';
    const publicJwk: PublicJWK = {
      kty: publicJwkRaw.kty!,
      kid: resolvedKid,
      use,
      alg: RSA_ALGORITHM,
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
    await this.store.add({
      kid: resolvedKid,
      use,
      alg: RSA_ALGORITHM,
      privateKey,
      publicKey,
      publicJwk,
      privateJwk,
    });
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

  public async encrypt(kid: string, input: Buffer): Promise<string> {
    const entry = this.store.get(kid);
    if (!entry) {
      throw new Error(`Missing kid (${kid}).`);
    }
    return new CompactEncrypt(Uint8Array.from(input))
      .setProtectedHeader({ enc: RSA_ENC, alg: RSA_ALGORITHM, kid })
      .encrypt(entry.publicKey);
  }

  public async decrypt(payload: string, store = this.store): Promise<JWKDecryptResult> {
    const keyResolver = async (header: JWEHeaderParameters) => {
      const keyEntry = store.get(header.kid);
      if (!keyEntry || !keyEntry.privateKey) {
        throw new Error('no key found');
      }
      return keyEntry.privateKey;
    };
    const { plaintext, protectedHeader } = await compactDecrypt(payload, keyResolver);
    const entry = store.get(protectedHeader.kid);
    const payloadBuffer = Buffer.from(plaintext);
    return {
      payload: payloadBuffer,
      plaintext: payloadBuffer,
      header: (protectedHeader as unknown) as Record<string, string>,
      protected: Object.keys(protectedHeader),
      key: {
        kty: entry!.publicJwk.kty,
        kid: entry!.publicJwk.kid,
        use: entry!.publicJwk.use,
        alg: entry!.publicJwk.alg,
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
    const publicKey = (await importJWK(publicJwk)) as KeyLike;
    if (isPrivate) {
      const privateJwk = key as PrivateJWK;
      const privateKey = (await importJWK(privateJwk)) as KeyLike;
      await store.add({
        kid: key.kid,
        use: key.use as KeyUse,
        alg: key.alg,
        privateKey,
        publicKey,
        publicJwk,
        privateJwk,
      });
    } else {
      await store.add({ kid: key.kid, use: key.use as KeyUse, alg: key.alg, publicKey, publicJwk });
    }
  }
  return store;
}

export async function createJWKSManager(jwks?: JWKS): Promise<JWKSManager> {
  const store = await createJWKS(jwks);
  return new JWKSManager(store);
}
