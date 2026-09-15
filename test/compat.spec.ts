import {
  createJWKManager,
  createJWKS,
  createJWKSManager,
  KeyStore,
  packBody,
  unpackBody,
} from '../src';

import { privateJWKS } from './fixture/private_jwks';
import { publicJWKS } from './fixture/public_jwks';

// Vectors generated from node-jose 2.2.0 on 2026-07-30 using the same 2048-bit RSA key pair
// as the test fixtures — ground truth for cross-version JWE compatibility.
const COMPAT_PLAINTEXT = '{"migratedFrom":"node-jose","version":"compat-test"}';

// node-jose always included zip=DEF by default; jose v5 CJS cannot decompress these tokens.
const NODE_JOSE_ZIP_TOKEN =
  'eyJ6aXAiOiJERUYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJLSUJBTkEifQ.Kx5YxeXrmHwFWblBMaq02bo_v-s110AwT-3MCmiAJMnYey6BLn4V_EGkZ9lMC61Tv8DCsUMTeJUd9fWoMGI-aaocuxaOzubrRsLUZ91ASg7HG6A_PwwJL4x_qMP-A0XsmiwrelGL0yYw3ev6U510S6MJ7qI4Gi-iuo5Y9J9a-hqs0YjtBVamY6nrle6eTimmVGRFeIZ-pIDPl_tenP-IpY5XmpPCYO9StFw8jeOTDrd1CIRVlxXAMqmwr1FjpZ7thOMOw5lsWh2QeYD1UnjRa7LrjM6yhSPK_bfgVEYPEFaMLGBrLNowURHRpIWd2gpFSX_pOXzfb8PgwMXzhYC_qw.Uy1qM7oB4vqL86aZ5L9Cow.A0xFHxMzfeTNYsNW1hWjcJ2aoUpiXETu4u9ufkkv8CY1R541LG-oPcHzMk6jxTN25jhSeUwwwYk2odUYrxMhsg.grNax6czYHGlGh-wUnlUpw'; // tslint:disable-line

// node-jose token without zip: RSA-OAEP + A128CBC-HS256, no compression — cross-version compat.
const NODE_JOSE_NO_ZIP_TOKEN =
  'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJLSUJBTkEifQ.nk9Xep8dScMJ2nczsuh6qctcMBKYj3lbBWGeNDza5mVjy3Inr34m3kou2nUGUxsilUGXc3mTq98RQj_9e4kPT6FO0nc8muwubWuSokRP0jzBx_1567DU2o9w-kQM0GT7P_pB4demLxuH-B6_QbnnzzvF3XZ7HK0FO4Z8xlfgaUGc6o8-7AwYBTI3bzTktLvgObnpCboDQKNIByI5krLKeCLqQAsG9EMNWljqe7YqX5-ZExa5-VZVH3hPSMyAXCvOcR-JTcWUPcS7z-03b3xJjnZnyhJpFEBxYf2oaWMtU3_dLaxvs9yrmMaKwtGVLznJYQzdBCHuDD4P-DY0mxFoMA.YdNY-HBbOl3e9BU_7PV2Tw.i2fN1HKzU4icUj9gWCjAhzW1Lrwvwut5JbhZNYzTjSMwmb0CHNENtFKfkeIAS45uAU1vFWlMlhZUftWXD0BfGg.W-3RmeRvR9gopHrJdWeiAA'; // tslint:disable-line

// Exactly what node-jose's util.base64url.encode(JSON.stringify({encryptedAESKey, encryptedPayload}), 'utf8') produces.
const NODE_JOSE_PACKED_BODY =
  'eyJlbmNyeXB0ZWRBRVNLZXkiOiJzZW50aW5lbC1hZXMta2V5LWZvci1wYWNrLXRlc3QiLCJlbmNyeXB0ZWRQYXlsb2FkIjoic2VudGluZWwtZW5jcnlwdGVkLXBheWxvYWQifQ'; // tslint:disable-line
const SENTINEL_AES_KEY = 'sentinel-aes-key-for-pack-test';
const SENTINEL_ENCRYPTED_PAYLOAD = 'sentinel-encrypted-payload';

describe('Migration compatibility — node-jose v2 → jose v5', () => {
  describe('packBody / unpackBody wire format', () => {
    it('packBody produces byte-identical output to node-jose util.base64url.encode', () => {
      expect(packBody(SENTINEL_AES_KEY, SENTINEL_ENCRYPTED_PAYLOAD)).to.equal(
        NODE_JOSE_PACKED_BODY
      );
    });
    it('unpackBody correctly parses a body that was packed by node-jose', () => {
      const { encryptedAESKey, encryptedPayload } = unpackBody(NODE_JOSE_PACKED_BODY);
      expect(encryptedAESKey).to.equal(SENTINEL_AES_KEY);
      expect(encryptedPayload).to.equal(SENTINEL_ENCRYPTED_PAYLOAD);
    });
  });

  describe('cross-version JWE decryption (RSA-OAEP + A128CBC-HS256, no zip)', () => {
    it('decrypts a token produced by node-jose without zip compression', async () => {
      const manager = await createJWKManager(privateJWKS);
      const result = await manager.decrypt(NODE_JOSE_NO_ZIP_TOKEN);
      expect(result.payload.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
      expect(result.plaintext.toString('utf8')).to.equal(COMPAT_PLAINTEXT);
    });
    it('payload and plaintext are both Buffers', async () => {
      const manager = await createJWKManager(privateJWKS);
      const result = await manager.decrypt(NODE_JOSE_NO_ZIP_TOKEN);
      expect(Buffer.isBuffer(result.payload)).to.equal(true);
      expect(Buffer.isBuffer(result.plaintext)).to.equal(true);
    });
    it('header matches the protected header fields that node-jose encoded', async () => {
      const manager = await createJWKManager(privateJWKS);
      const result = await manager.decrypt(NODE_JOSE_NO_ZIP_TOKEN);
      expect(result.header).to.eql({ enc: 'A128CBC-HS256', alg: 'RSA-OAEP', kid: 'KIBANA' });
    });
    it('protected lists exactly the names present in the node-jose header', async () => {
      const manager = await createJWKManager(privateJWKS);
      const result = await manager.decrypt(NODE_JOSE_NO_ZIP_TOKEN);
      expect(result.protected).to.have.members(['enc', 'alg', 'kid']);
    });
    it('key has kty / kid / use / alg and no longer carries length or keystore', async () => {
      const manager = await createJWKManager(privateJWKS);
      const result = await manager.decrypt(NODE_JOSE_NO_ZIP_TOKEN);
      expect(result.key).to.have.keys(['kty', 'kid', 'use', 'alg']);
      expect(result.key).to.not.have.property('length');
      expect(result.key).to.not.have.property('keystore');
    });
  });

  describe('zip-compressed tokens (old node-jose default)', () => {
    it('rejects a zip-compressed token with an error that identifies zip as the cause', async () => {
      const manager = await createJWKManager(privateJWKS);
      let errorMessage = '';
      try {
        await manager.decrypt(NODE_JOSE_ZIP_TOKEN);
      } catch (err) {
        errorMessage = (err as Error).message;
      }
      expect(errorMessage).to.include('zip');
    });
  });

  describe('new token format (RFC 7516 standard)', () => {
    it('tokens produced by encrypt have enc / alg / kid header but no zip field', async () => {
      const manager = await createJWKManager(publicJWKS);
      const token = await manager.encrypt('KIBANA', Buffer.from('hello', 'utf8'));
      const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
      expect(header.enc).to.equal('A128CBC-HS256');
      expect(header.alg).to.equal('RSA-OAEP');
      expect(header.kid).to.equal('KIBANA');
      expect(header).to.not.have.property('zip');
    });
  });

  describe('JWKSManager.store is a KeyStore instance', () => {
    it('store property holds a real KeyStore (was typed as any in node-jose version)', async () => {
      const manager = await createJWKSManager(privateJWKS);
      expect(manager.store).to.be.instanceOf(KeyStore);
    });
  });

  describe('createJWKS', () => {
    it('returns an empty KeyStore when called with no arguments', async () => {
      const store = await createJWKS();
      expect(store).to.be.instanceOf(KeyStore);
      expect(store.toJSON().keys).to.have.length(0);
    });
    it('loads private key entries — get and remove work against the same fixture JWKS', async () => {
      const store = await createJWKS(privateJWKS);
      expect(store.get('KIBANA')).to.not.equal(undefined);
      store.remove(privateJWKS.keys[0]);
      expect(store.get('KIBANA')).to.equal(undefined);
    });
  });
});
