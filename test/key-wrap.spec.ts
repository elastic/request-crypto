import {
  createJWKManager,
  createRequestDecryptor,
  createRequestEncryptor,
  KEY_WRAP_ALGORITHM,
  KeyWrapInfo,
  LEGACY_KEY_WRAP_ALGORITHM,
  MAX_DECOMPRESSED_LENGTH,
  packBody,
  unpackBody,
} from '../src';

import * as largePayload from './fixture/large_payload.json';
import { privateJWKS } from './fixture/private_jwks';
import { publicJWKS } from './fixture/public_jwks';
import { encryptWithLegacyKeyWrap, readProtectedHeader, tamperProtectedHeader } from './helpers';

// Frozen vector produced by node-jose 2.2.0 on 2026-09-02 against the same 2048-bit key pair as the
// fixtures, wrapping with RSA-OAEP-256. node-jose constrains a key to the algorithm named in its
// JWK "alg" member, so the key was imported without "alg" to be able to wrap with SHA-256. This is
// ground truth that RSA-OAEP-256 tokens are decryptable across libraries, not just round-trippable
// within jose.
const NODE_JOSE_RSA_OAEP_256_TOKEN =
  'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJ6aXAiOiJERUYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiS0lCQU5BIn0.MQ8jsT9Ey4-M9iZYMVKWvh6BjS-uNZn8tTrgvdWfL2Rpz4qPRMWTNWODN-86Mq2HtGLzLnkzf0SjVQF2nEsuL5XM_wmJUydkD4_7dY_yP13aUuBD3YkKeWkO6Y7C9PInSdyNbMC1ug00QqkXVJnSXN_upBpBW8elWiBg1CVOfZ_IsmSEXoAOXUlaJF-Cs3j_xQ9AmOCrOBJT4u35CGac_1vGqNzc2EUtNBvZ0C0VA2Q4uvbFzQvIEm1EZMx-bHpsX8NIkcN2RJTOwEZBxjSAi0etz6_zmIYC_wx7L1_lGPIq0_BSV9IlZh5P9T4HW0xlceC_p2SSxC4M2g9af61BAw.sm3p4uoY3iOKdOZvtM7vFw.zbNn_lqHE3hHY2CKyoG0T8_RbSOp_O7Ph3W5Ai41wTMcV6f88VUytpRwRlJf09uZCWZKpWLpJuiT4wGGsq9kWw.gapPqt49ubAFjE8mauMFZg'; // tslint:disable-line

// Same plaintext as the legacy vectors in compat.spec.ts — both were generated from it.
const COMPAT_PLAINTEXT = '{"migratedFrom":"node-jose","version":"compat-test"}';

// The legacy vector from compat.spec.ts, kept here too so one manager can be exercised with both
// algorithms interleaved.
const NODE_JOSE_LEGACY_TOKEN =
  'eyJ6aXAiOiJERUYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJLSUJBTkEifQ.Kx5YxeXrmHwFWblBMaq02bo_v-s110AwT-3MCmiAJMnYey6BLn4V_EGkZ9lMC61Tv8DCsUMTeJUd9fWoMGI-aaocuxaOzubrRsLUZ91ASg7HG6A_PwwJL4x_qMP-A0XsmiwrelGL0yYw3ev6U510S6MJ7qI4Gi-iuo5Y9J9a-hqs0YjtBVamY6nrle6eTimmVGRFeIZ-pIDPl_tenP-IpY5XmpPCYO9StFw8jeOTDrd1CIRVlxXAMqmwr1FjpZ7thOMOw5lsWh2QeYD1UnjRa7LrjM6yhSPK_bfgVEYPEFaMLGBrLNowURHRpIWd2gpFSX_pOXzfb8PgwMXzhYC_qw.Uy1qM7oB4vqL86aZ5L9Cow.A0xFHxMzfeTNYsNW1hWjcJ2aoUpiXETu4u9ufkkv8CY1R541LG-oPcHzMk6jxTN25jhSeUwwwYk2odUYrxMhsg.grNax6czYHGlGh-wUnlUpw'; // tslint:disable-line

const smallPayload = { some: 'payload', nested: { count: 3 } };

/** Strips the optional "alg" member from a JWK — it is not required by RFC 7517. */
function withoutAlg<T extends { alg: string }>(jwk: T): any {
  const copy = { ...jwk } as any;
  delete copy.alg;
  return copy;
}

async function captureError(fn: () => Promise<unknown>): Promise<Error> {
  try {
    await fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error('expected the operation to throw, but it resolved');
}

describe('Key wrap algorithm — RSA-OAEP-256 out, RSA-OAEP or RSA-OAEP-256 in', () => {
  describe('encryption side (exclusively RSA-OAEP-256)', () => {
    it('emits RSA-OAEP-256 even though the public JWK is stamped alg: RSA-OAEP', async () => {
      // This is the production shape: the public keys Kibana ships say alg: "RSA-OAEP".
      expect(publicJWKS.keys[0].alg).to.equal(LEGACY_KEY_WRAP_ALGORITHM);

      const manager = await createJWKManager(publicJWKS);
      const token = await manager.encrypt('KIBANA', Buffer.from('hello', 'utf8'));

      expect(readProtectedHeader(token).alg).to.equal(KEY_WRAP_ALGORITHM);
    });

    it('leaves the rest of the protected header untouched', async () => {
      const manager = await createJWKManager(publicJWKS);
      const token = await manager.encrypt('KIBANA', Buffer.from('hello', 'utf8'));

      expect(readProtectedHeader(token)).to.eql({
        zip: 'DEF',
        enc: 'A128CBC-HS256',
        alg: 'RSA-OAEP-256',
        kid: 'KIBANA',
      });
    });

    it('never emits the legacy key wrap, including through the request encryptor', async () => {
      const encryptor = await createRequestEncryptor(publicJWKS);
      const body = await encryptor.encrypt('KIBANA', smallPayload);

      const decryptor = await createRequestDecryptor(privateJWKS);
      const metadata = await decryptor.getJWKMetadata(body);
      expect(metadata.header.alg).to.equal(KEY_WRAP_ALGORITHM);
    });
  });

  describe('decryption side (accepts both, selected by the token header)', () => {
    it('round trips a request encrypted with RSA-OAEP-256', async () => {
      const encryptor = await createRequestEncryptor(publicJWKS);
      const decryptor = await createRequestDecryptor(privateJWKS);

      const body = await encryptor.encrypt('KIBANA', smallPayload);
      expect(await decryptor.decrypt(body)).to.eql(smallPayload);
    });

    it('decrypts a request from an un-upgraded sender still using RSA-OAEP', async () => {
      const legacyBody = await encryptWithLegacyKeyWrap(publicJWKS.keys[0], 'KIBANA', smallPayload);
      const decryptor = await createRequestDecryptor(privateJWKS);

      expect(await decryptor.decrypt(legacyBody)).to.eql(smallPayload);
    });

    it('decrypts a frozen RSA-OAEP-256 token produced by node-jose', async () => {
      const manager = await createJWKManager(privateJWKS);
      const result = await manager.decrypt(NODE_JOSE_RSA_OAEP_256_TOKEN);

      expect(result.header.alg).to.equal(KEY_WRAP_ALGORITHM);
      expect(result.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
    });

    it('decrypts a frozen legacy RSA-OAEP token produced by node-jose', async () => {
      const manager = await createJWKManager(privateJWKS);
      const result = await manager.decrypt(NODE_JOSE_LEGACY_TOKEN);

      expect(result.header.alg).to.equal(LEGACY_KEY_WRAP_ALGORITHM);
      expect(result.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
    });

    it('handles both algorithms interleaved on one manager, in either order', async () => {
      // Guards the per-algorithm key import cache: a key imported for one OAEP hash must never be
      // handed to a token that names the other.
      const manager = await createJWKManager(privateJWKS);
      const ownToken = await (await createJWKManager(publicJWKS)).encrypt(
        'KIBANA',
        Buffer.from(COMPAT_PLAINTEXT, 'utf8')
      );

      for (const token of [
        NODE_JOSE_LEGACY_TOKEN,
        NODE_JOSE_RSA_OAEP_256_TOKEN,
        NODE_JOSE_LEGACY_TOKEN,
        ownToken,
        NODE_JOSE_LEGACY_TOKEN,
      ]) {
        const result = await manager.decrypt(token);
        expect(result.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
      }
    });

    it('decrypts concurrent legacy and RSA-OAEP-256 tokens on one manager', async () => {
      const manager = await createJWKManager(privateJWKS);
      const results = await Promise.all([
        manager.decrypt(NODE_JOSE_LEGACY_TOKEN),
        manager.decrypt(NODE_JOSE_RSA_OAEP_256_TOKEN),
        manager.decrypt(NODE_JOSE_LEGACY_TOKEN),
      ]);

      expect(results.map(r => r.header.alg)).to.eql([
        LEGACY_KEY_WRAP_ALGORITHM,
        KEY_WRAP_ALGORITHM,
        LEGACY_KEY_WRAP_ALGORITHM,
      ]);
      results.forEach(result => {
        expect(result.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
      });
    });
  });

  describe("the JWK's own alg member does not gate anything", () => {
    it('decrypts a legacy token with a key stamped alg: RSA-OAEP-256', async () => {
      // Keys generated by this version are stamped with the new algorithm, but must still be able
      // to read tokens from senders that wrapped with the legacy one.
      const stampedNew = { keys: [{ ...privateJWKS.keys[0], alg: KEY_WRAP_ALGORITHM }] };
      const manager = await createJWKManager(stampedNew);

      const result = await manager.decrypt(NODE_JOSE_LEGACY_TOKEN);
      expect(result.header.alg).to.equal(LEGACY_KEY_WRAP_ALGORITHM);
      expect(result.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
    });

    it('loads and decrypts both algorithms from a JWKS with no alg member', async () => {
      // "alg" is optional in a JWK (RFC 7517 §4.4). Deriving the algorithm from the token instead
      // of the key means such a JWKS works; taking it from the key made this throw on load.
      const manager = await createJWKManager({ keys: [withoutAlg(privateJWKS.keys[0])] });
      const encryptManager = await createJWKManager({ keys: [withoutAlg(publicJWKS.keys[0])] });

      const ownToken = await encryptManager.encrypt(
        'KIBANA',
        Buffer.from(COMPAT_PLAINTEXT, 'utf8')
      );
      expect(readProtectedHeader(ownToken).alg).to.equal(KEY_WRAP_ALGORITHM);

      for (const token of [NODE_JOSE_LEGACY_TOKEN, ownToken]) {
        expect((await manager.decrypt(token)).payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
      }
    });

    it('serves a different algorithm per kid from one JWKS', async () => {
      // Production JWKS hold several keys (kibana1, kibana_dev1). Mixed traffic means one key can
      // be receiving legacy tokens while another receives new ones, on distinct key material.
      const rotated = await createJWKManager();
      await rotated.addKey('KIBANA_2');
      const secondKey = rotated.getPrivateJWK('KIBANA_2')!;
      expect(secondKey.alg).to.equal(KEY_WRAP_ALGORITHM);

      const manager = await createJWKManager({ keys: [privateJWKS.keys[0], secondKey] });
      const newToken = await rotated.encrypt('KIBANA_2', Buffer.from(COMPAT_PLAINTEXT, 'utf8'));

      const legacyResult = await manager.decrypt(NODE_JOSE_LEGACY_TOKEN);
      const newResult = await manager.decrypt(newToken);

      expect([legacyResult.header.kid, legacyResult.header.alg]).to.eql([
        'KIBANA',
        LEGACY_KEY_WRAP_ALGORITHM,
      ]);
      expect([newResult.header.kid, newResult.header.alg]).to.eql(['KIBANA_2', KEY_WRAP_ALGORITHM]);
      expect(legacyResult.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
      expect(newResult.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
    });
  });

  describe('legacy requests through the full request path', () => {
    it('reports legacy metadata through getJWKMetadata', async () => {
      const legacyBody = await encryptWithLegacyKeyWrap(publicJWKS.keys[0], 'KIBANA', smallPayload);
      const decryptor = await createRequestDecryptor(privateJWKS);

      const metadata = await decryptor.getJWKMetadata(legacyBody);
      expect(metadata.header.alg).to.equal(LEGACY_KEY_WRAP_ALGORITHM);
      expect(metadata.protected).to.eql(['zip', 'enc', 'alg', 'kid']);
      expect(metadata.key.kid).to.equal('KIBANA');
    });

    it('decrypts a large legacy payload', async () => {
      const legacyBody = await encryptWithLegacyKeyWrap(publicJWKS.keys[0], 'KIBANA', largePayload);
      const decryptor = await createRequestDecryptor(privateJWKS);

      expect(await decryptor.decrypt(legacyBody)).to.eql(largePayload);
    });
  });

  describe('pinned algorithms', () => {
    it('rejects a key wrap algorithm outside the allowlist', async () => {
      const manager = await createJWKManager(privateJWKS);
      const tampered = tamperProtectedHeader(NODE_JOSE_RSA_OAEP_256_TOKEN, { alg: 'RSA1_5' });

      const err = await captureError(() => manager.decrypt(tampered));
      expect((err as any).code).to.equal('ERR_JOSE_ALG_NOT_ALLOWED');
    });

    it('rejects a content encryption algorithm outside the allowlist', async () => {
      const manager = await createJWKManager(privateJWKS);
      const tampered = tamperProtectedHeader(NODE_JOSE_RSA_OAEP_256_TOKEN, { enc: 'A256GCM' });

      const err = await captureError(() => manager.decrypt(tampered));
      expect((err as any).code).to.equal('ERR_JOSE_ALG_NOT_ALLOWED');
    });

    it('rejects a compressed token that would inflate past the limit', async () => {
      const encryptManager = await createJWKManager(publicJWKS);
      const decryptManager = await createJWKManager(privateJWKS);
      const oversized = Buffer.from('A'.repeat(MAX_DECOMPRESSED_LENGTH + 1), 'utf8');

      // A highly compressible payload makes the token tiny; only the inflate limit catches it.
      const token = await encryptManager.encrypt('KIBANA', oversized);
      expect(token.length).to.be.below(2000);

      const err = await captureError(() => decryptManager.decrypt(token));
      expect((err as any).code).to.equal('ERR_JWE_INVALID');
      expect(err.message).to.contain('Decompressed plaintext exceeded the configured limit');
    });

    it('still accepts a compressed token inside the limit', async () => {
      const encryptManager = await createJWKManager(publicJWKS);
      const decryptManager = await createJWKManager(privateJWKS);
      const payload = Buffer.from('A'.repeat(MAX_DECOMPRESSED_LENGTH - 1), 'utf8');

      const token = await encryptManager.encrypt('KIBANA', payload);
      const result = await decryptManager.decrypt(token);
      expect(result.payload.length).to.equal(payload.length);
    });
  });

  describe('onKeyWrap instrumentation', () => {
    it('reports the legacy algorithm for a token from an un-upgraded sender', async () => {
      const seen: KeyWrapInfo[] = [];
      const decryptor = await createRequestDecryptor(privateJWKS, {
        onKeyWrap: info => seen.push(info),
      });

      const legacyBody = await encryptWithLegacyKeyWrap(publicJWKS.keys[0], 'KIBANA', smallPayload);
      await decryptor.decrypt(legacyBody);

      expect(seen).to.eql([{ kid: 'KIBANA', alg: LEGACY_KEY_WRAP_ALGORITHM, legacy: true }]);
    });

    it('reports the new algorithm for a token from an upgraded sender', async () => {
      const seen: KeyWrapInfo[] = [];
      const encryptor = await createRequestEncryptor(publicJWKS);
      const decryptor = await createRequestDecryptor(privateJWKS, {
        onKeyWrap: info => seen.push(info),
      });

      await decryptor.decrypt(await encryptor.encrypt('KIBANA', smallPayload));

      expect(seen).to.eql([{ kid: 'KIBANA', alg: KEY_WRAP_ALGORITHM, legacy: false }]);
    });

    it('reports through getJWKMetadata as well', async () => {
      const seen: KeyWrapInfo[] = [];
      const encryptor = await createRequestEncryptor(publicJWKS);
      const decryptor = await createRequestDecryptor(privateJWKS, {
        onKeyWrap: info => seen.push(info),
      });

      await decryptor.getJWKMetadata(await encryptor.encrypt('KIBANA', smallPayload));

      expect(seen).to.have.length(1);
      expect(seen[0].legacy).to.equal(false);
    });

    it('does not fail a request when the hook throws', async () => {
      const encryptor = await createRequestEncryptor(publicJWKS);
      const decryptor = await createRequestDecryptor(privateJWKS, {
        onKeyWrap: () => {
          throw new Error('metrics backend is down');
        },
      });

      const body = await encryptor.encrypt('KIBANA', smallPayload);
      expect(await decryptor.decrypt(body)).to.eql(smallPayload);
    });

    it('does not fail a request when an async hook rejects', async () => {
      const unhandled: Array<unknown> = [];
      const onUnhandled = (reason: unknown) => {
        unhandled.push(reason);
      };
      process.on('unhandledRejection', onUnhandled);
      try {
        const encryptor = await createRequestEncryptor(publicJWKS);
        const decryptor = await createRequestDecryptor(privateJWKS, {
          onKeyWrap: async () => {
            throw new Error('metrics backend is down');
          },
        });

        const body = await encryptor.encrypt('KIBANA', smallPayload);
        expect(await decryptor.decrypt(body)).to.eql(smallPayload);
        await new Promise(resolve => setImmediate(resolve));
        expect(unhandled).to.eql([]);
      } finally {
        process.removeListener('unhandledRejection', onUnhandled);
      }
    });

    it('does not count a request whose payload fails to authenticate', async () => {
      // A valid JWE paired with a payload encrypted under a different passphrase. The key wrap
      // resolves, so a hook that fired before the payload authenticated would count this request
      // even though decrypt rejects it.
      const seen: KeyWrapInfo[] = [];
      const encryptor = await createRequestEncryptor(publicJWKS);
      const decryptor = await createRequestDecryptor(privateJWKS, {
        onKeyWrap: info => seen.push(info),
      });
      const first = await encryptor.encrypt('KIBANA', smallPayload);
      const second = await encryptor.encrypt('KIBANA', smallPayload);
      const mismatched = packBody(
        unpackBody(first).encryptedAESKey,
        unpackBody(second).encryptedPayload
      );

      const err = await captureError(() => decryptor.decrypt(mismatched));
      expect(err.message).to.contain('unable to authenticate data');
      expect(seen).to.eql([]);

      // The algorithm of the failed request is still recoverable, which is the path a receiver
      // uses from its error handler.
      const metadata = await decryptor.getJWKMetadata(mismatched);
      expect(metadata.header.alg).to.equal(KEY_WRAP_ALGORITHM);
      expect(seen).to.eql([{ kid: 'KIBANA', alg: KEY_WRAP_ALGORITHM, legacy: false }]);
    });

    it('is optional — decryption works with no options at all', async () => {
      const encryptor = await createRequestEncryptor(publicJWKS);
      const decryptor = await createRequestDecryptor(privateJWKS);

      const body = await encryptor.encrypt('KIBANA', smallPayload);
      expect(await decryptor.decrypt(body)).to.eql(smallPayload);
    });
  });
});
