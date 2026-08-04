import { CONTENT_ALGORITHM, encryptCompact, ZIP_DEFLATE } from '../src/jwe';
import { createJWKSManager, RSA_ALGORITHM } from '../src/jwks';
import { createRequestDecryptor, packBody, unpackBody } from '../src/request';

import { encryptedRequest } from './fixture/encrypted_jwk';
import {
  noZipPlaintext,
  noZipToken,
  packedBody,
  packedBodySentinel,
  packedBodySentinelAESKey,
  packedBodySentinelPayload,
  zipKeyMeta,
  zipPlaintext,
  zipToken,
} from './fixture/node_jose_vectors';
import { privateJWKS } from './fixture/private_jwks';

describe('node-jose compatibility', () => {
  describe('decrypt node-jose zip token', () => {
    it('decrypts zip token to correct plaintext', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const result = await manager.decrypt(zipToken);
      expect(result.plaintext.toString('utf8')).to.equal(zipPlaintext);
    });

    it('protected fields are in node-jose insertion order', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const result = await manager.decrypt(zipToken);
      expect(result.protected).to.eql(['zip', 'enc', 'alg', 'kid']);
    });

    it('payload === plaintext (same Buffer object)', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const result = await manager.decrypt(zipToken);
      expect(result.payload).to.equal(result.plaintext);
    });

    it('key metadata matches node-jose shape (no keystore back-ref)', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const result = await manager.decrypt(zipToken);
      expect(result.key).to.eql(zipKeyMeta);
      expect(Object.keys(result.key)).to.eql(['length', 'kty', 'kid', 'use', 'alg']);
    });
  });

  describe('decrypt node-jose no-zip token', () => {
    it('decrypts no-zip token to correct plaintext', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const result = await manager.decrypt(noZipToken);
      expect(result.plaintext.toString('utf8')).to.equal(noZipPlaintext);
    });

    it('protected fields exclude zip when absent', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const result = await manager.decrypt(noZipToken);
      expect(result.protected).to.eql(['enc', 'alg', 'kid']);
    });
  });

  describe('packBody / unpackBody compat with node-jose util.base64url', () => {
    it('packBody sentinel matches node-jose util.base64url.encode byte-for-byte', () => {
      const result = packBody(packedBodySentinelAESKey, packedBodySentinelPayload);
      expect(result).to.equal(packedBodySentinel);
    });

    it('unpackBody round-trips packBody', () => {
      const packed = packBody('key-value', 'payload-value');
      const { encryptedAESKey, encryptedPayload } = unpackBody(packed);
      expect(encryptedAESKey).to.equal('key-value');
      expect(encryptedPayload).to.equal('payload-value');
    });

    it('unpackBody handles multi-byte UTF-8', () => {
      const key = 'key-é-中文';
      const payload = 'payload-é-中文';
      const packed = packBody(key, payload);
      const { encryptedAESKey, encryptedPayload } = unpackBody(packed);
      expect(encryptedAESKey).to.equal(key);
      expect(encryptedPayload).to.equal(payload);
    });
  });

  describe('createRequestDecryptor decrypts node-jose packed body', () => {
    it('decrypts frozen packedBody end-to-end', async () => {
      const decryptor = await createRequestDecryptor(privateJWKS);
      const result = await decryptor.decrypt(packedBody);
      expect(result).to.be.an('object');
      expect((result as any).test).to.equal('packed-body-compat');
      expect((result as any).source).to.equal('node-jose');
    });
  });

  describe('our own encrypt output has node-jose header member order', () => {
    it('header members are in zip,enc,alg,kid order', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const token = await manager.encrypt('KIBANA', Buffer.from('hello', 'utf8'));
      const headerB64 = token.split('.')[0];
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
      expect(Object.keys(header)).to.eql(['zip', 'enc', 'alg', 'kid']);
    });
  });

  describe('frozen KIBANA_7.0 token parses without its private key', () => {
    it('yields no key found on decrypt attempt', async () => {
      const manager = await createJWKSManager(privateJWKS);
      let errorMessage = '';
      try {
        await manager.decrypt(encryptedRequest.encryptedKey);
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.equal('Error: no key found');
    });
  });

  describe('no-kid token resolves against first key', () => {
    it('decrypts when token has no kid', async () => {
      const manager = await createJWKSManager(privateJWKS);
      const key = manager.store.get('KIBANA');
      const token = encryptCompact(
        key.publicKey,
        { zip: ZIP_DEFLATE, enc: CONTENT_ALGORITHM, alg: RSA_ALGORITHM },
        Buffer.from('hello no-kid', 'utf8')
      );
      const result = await manager.decrypt(token);
      expect(result.plaintext.toString('utf8')).to.equal('hello no-kid');
    });
  });
});
