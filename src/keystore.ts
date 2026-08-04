import * as crypto from 'crypto';
import {
  JWK,
  JWKMetadata,
  JWKS,
  KeyUse,
  PrivateJWK,
  PrivateJWKS,
  PublicJWK,
  PublicJWKS,
} from './jwks';

export interface KeyFilter {
  kid?: string;
  kty?: string;
  use?: string;
  alg?: string;
}

export interface StoredKey {
  kty: string;
  kid: string;
  use: string; // '' when absent — node-jose parity
  alg: string; // '' when absent
  length: number; // RSA modulus size in bits
  isPrivate: boolean;
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject | null;
  toJSON(isPrivate?: boolean): PublicJWK | PrivateJWK;
  metadata(): JWKMetadata;
}

// node-jose filter semantics: skip each attribute check when either the filter value
// or the key's own value is falsy. The falsy-skip on kid is what makes a no-kid token
// resolve against the first key in the store.
function matchesFilter(key: StoredKey, filter: KeyFilter): boolean {
  if (filter.kid && key.kid && filter.kid !== key.kid) {
    return false;
  }
  if (filter.use && key.use && filter.use !== key.use) {
    return false;
  }
  if (filter.alg && key.alg && filter.alg !== key.alg) {
    return false;
  }
  if (filter.kty && key.kty && filter.kty !== key.kty) {
    return false;
  }
  return true;
}

export class KeyStore {
  // Array, not Map — target: ES5 with no downlevelIteration; insertion order preserved.
  private keys: StoredKey[];

  constructor() {
    this.keys = [];
  }

  // Accepts JWK | Buffer | string; a StoredKey is deep-copied via toJSON(true).
  // Stays async so store.add(x).then(...) keeps working and throws surface as rejections.
  public async add(input: JWK | Buffer | string, form?: string): Promise<StoredKey> {
    const key = importKey(input, form);
    this.keys.push(key);
    return key;
  }

  // get() with no argument returns the first key.
  // get(string) filters by kid. get(KeyFilter) uses the node-jose filter semantics above.
  public get(kidOrFilter?: string | KeyFilter): StoredKey | null {
    if (kidOrFilter === undefined) {
      return this.keys.length > 0 ? this.keys[0] : null;
    }
    if (typeof kidOrFilter === 'string') {
      return this.all({ kid: kidOrFilter })[0] || null;
    }
    return this.all(kidOrFilter)[0] || null;
  }

  public all(filter?: KeyFilter): StoredKey[] {
    if (filter === undefined) {
      return this.keys.slice();
    }
    return this.keys.filter(k => matchesFilter(k, filter));
  }

  // remove — the bug fix: actually removes entries with the matching kid.
  // Silent no-op for unknown / undefined / null input. Removes ALL entries with that kid.
  public remove(input?: JWK | StoredKey | string | null): void {
    if (!input) {
      return;
    }
    const kid = typeof input === 'string' ? input : input.kid;
    if (!kid) {
      return;
    }
    this.keys = this.keys.filter(k => k.kid !== kid);
  }

  public toJSON(isPrivate?: boolean): PublicJWKS | PrivateJWKS {
    return {
      keys: this.keys.map(k => k.toJSON(isPrivate)),
    };
  }
}

// RFC 7638 JWK Thumbprint for RSA keys: sha256(JSON.stringify({e,kty,n})) in base64url.
// Members must be in lexicographic order: e, kty, n.
export function jwkThumbprint(jwk: { kty: string; n: string; e: string }): string {
  const canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  return crypto
    .createHash('sha256')
    .update(canonical)
    .digest()
    .toString('base64url');
}

export function isJWKS(input: any): input is JWKS {
  return (
    input !== null &&
    typeof input === 'object' &&
    !Array.isArray(input) &&
    Array.isArray(input.keys)
  );
}

// Imports a JWK (or JSON Buffer/string) into a StoredKey.
// Throws synchronously on invalid input. Called by KeyStore.add via async wrapper.
export function importKey(input: JWK | Buffer | string, form?: string): StoredKey {
  if (form !== undefined && form !== 'json') {
    throw new Error('unsupported form: ' + form);
  }

  let raw: any;
  if (Buffer.isBuffer(input)) {
    raw = JSON.parse(input.toString('utf8'));
  } else if (typeof input === 'string') {
    raw = JSON.parse(input);
  } else {
    // Plain object: copy so we never retain the caller's reference.
    raw = Object.assign({}, input);
  }

  if (raw === null || typeof raw !== 'object' || Array.isArray(raw) || raw.kty !== 'RSA') {
    throw new Error('unsupported key type');
  }

  const pjwk: PrivateJWK = raw as PrivateJWK;
  const pub: PublicJWK = raw as PublicJWK;
  const isPrivate = typeof pjwk.d === 'string' && pjwk.d.length > 0;

  // Build fresh object literals to satisfy crypto.JsonWebKey's index signature;
  // this also strips kid/use/alg so Node does not try to interpret them.
  const publicJwkRaw = { kty: pub.kty, n: pub.n, e: pub.e };
  const publicKey = crypto.createPublicKey({ key: publicJwkRaw, format: 'jwk' });

  let privateKey: crypto.KeyObject | null = null;
  if (isPrivate) {
    const privateJwkRaw = {
      kty: pjwk.kty,
      n: pjwk.n,
      e: pjwk.e,
      d: pjwk.d,
      p: pjwk.p,
      q: pjwk.q,
      dp: pjwk.dp,
      dq: pjwk.dq,
      qi: pjwk.qi,
    };
    privateKey = crypto.createPrivateKey({ key: privateJwkRaw, format: 'jwk' });
  }

  // asymmetricKeyDetails is optional at both levels (strictNullChecks guard required).
  const details = publicKey.asymmetricKeyDetails;
  const length =
    details !== undefined && details.modulusLength !== undefined ? details.modulusLength : 0;

  const rawKid: string = pub.kid || '';
  const kid = rawKid.length > 0 ? rawKid : jwkThumbprint(pub);
  const use: string = pub.use || '';
  const alg: string = pub.alg || '';

  // Precompute exported JWK — byte-identical round-trip for n/e/d/p/q/dp/dq/qi.
  // Return Object.assign({}, cached) per call so callers cannot mutate the store.
  const exportedPub = publicKey.export({ format: 'jwk' });
  const exportedPriv: crypto.JsonWebKey | null =
    isPrivate && privateKey !== null
      ? (privateKey as crypto.KeyObject).export({ format: 'jwk' })
      : null;

  function makePublicJSON(): PublicJWK {
    const result: any = { kty: 'RSA', kid };
    if (use) {
      result.use = use;
    }
    if (alg) {
      result.alg = alg;
    }
    result.e = exportedPub.e as string;
    result.n = exportedPub.n as string;
    return result as PublicJWK;
  }

  function toJSON(includePrivate?: boolean): PublicJWK | PrivateJWK {
    if (includePrivate && isPrivate && exportedPriv !== null) {
      const result: any = { kty: 'RSA', kid };
      if (use) {
        result.use = use;
      }
      if (alg) {
        result.alg = alg;
      }
      result.e = exportedPub.e as string;
      result.n = exportedPub.n as string;
      result.d = exportedPriv.d as string;
      result.p = exportedPriv.p as string;
      result.q = exportedPriv.q as string;
      result.dp = exportedPriv.dp as string;
      result.dq = exportedPriv.dq as string;
      result.qi = exportedPriv.qi as string;
      return result as PrivateJWK;
    }
    return makePublicJSON();
  }

  const storedKey: StoredKey = {
    kty: 'RSA',
    kid,
    use,
    alg,
    length,
    isPrivate,
    publicKey,
    privateKey,
    toJSON,
    metadata(): JWKMetadata {
      return { length, kty: 'RSA', kid, use: use as KeyUse | 'sig', alg };
    },
  };
  return storedKey;
}

// Generates a new RSA key pair and returns the result as a PrivateJWK.
// Wrapped in a Promise directly to avoid util.promisify's overload complexity.
export function generateJWK(
  modulusLength: number,
  config: { alg: string; use: KeyUse; kid?: string }
): Promise<PrivateJWK> {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
      { modulusLength, publicExponent: 0x10001 },
      (err, publicKey, privateKey) => {
        if (err) {
          return reject(err);
        }
        const exportedPub = publicKey.export({ format: 'jwk' });
        const exportedPriv = privateKey.export({ format: 'jwk' });
        const configKid: string = config.kid || '';
        const kid = configKid.length > 0 ? configKid : crypto.randomUUID();
        // Assemble in node-jose's member order: kty, kid, use, alg, e, n, d, p, q, dp, dq, qi
        const jwk: PrivateJWK = {
          kty: 'RSA',
          kid,
          use: config.use,
          alg: config.alg,
          e: exportedPub.e as string,
          n: exportedPub.n as string,
          d: exportedPriv.d as string,
          p: exportedPriv.p as string,
          q: exportedPriv.q as string,
          dp: exportedPriv.dp as string,
          dq: exportedPriv.dq as string,
          qi: exportedPriv.qi as string,
        };
        resolve(jwk);
      }
    );
  });
}
