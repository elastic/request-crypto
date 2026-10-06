import { calculateJwkThumbprint } from 'jose';

import { createJWKManager } from '../src/jwk';

import { privateJWKS } from './fixture/private_jwks';
import { publicJWKS } from './fixture/public_jwks';

describe('JSON Web Keys Manager', () => {
  describe('JWKS', () => {
    it('creates an empty key set', async () => {
      const manager = await createJWKManager();
      const jwks = manager.getPrivateJWKS();

      expect(jwks).to.eql({ keys: [] });
    });
    it('prepopulates public key sets', async () => {
      const manager = await createJWKManager(publicJWKS);
      expect(manager.getPrivateJWKS()).to.eql(publicJWKS);
      expect(manager.getPublicJWKS()).to.eql(publicJWKS);
    });
    it('prepopulates private key sets', async () => {
      const manager = await createJWKManager(privateJWKS);
      expect(manager.getPrivateJWKS()).to.eql(privateJWKS);
      expect(manager.getPublicJWKS()).to.eql(publicJWKS);
    });
    it('adds a new key to the set', async () => {
      const manager = await createJWKManager();
      await manager.addKey('KIBANA_2');
      const { keys } = manager.getPrivateJWKS();
      expect(keys).to.have.length(1);
    });
  });

  describe('Generated keys', () => {
    it('stamps the RSA-OAEP-256 key wrap algorithm on new keys', async () => {
      const manager = await createJWKManager();
      await manager.addKey('KIBANA_NEW');

      expect(manager.getPublicJWK('KIBANA_NEW')!.alg).to.equal('RSA-OAEP-256');
      expect(manager.getPrivateJWK('KIBANA_NEW')!.alg).to.equal('RSA-OAEP-256');
    });

    it('derives an RFC 7638 thumbprint kid when none is supplied', async () => {
      const manager = await createJWKManager();
      await manager.addKey();

      const [key] = manager.getPublicJWKS().keys;
      expect(key.kid).to.equal(
        await calculateJwkThumbprint(key as Parameters<typeof calculateJwkThumbprint>[0])
      );
    });

    it('keeps unnamed keys distinct instead of collapsing them onto one entry', async () => {
      const manager = await createJWKManager();
      await manager.addKey();
      await manager.addKey();

      const { keys } = manager.getPrivateJWKS();
      expect(keys).to.have.length(2);
      expect(keys[0].kid).to.not.equal(keys[1].kid);
      // Both must be individually addressable — an empty-string kid would shadow the second key.
      expect(manager.getPrivateJWK(keys[0].kid)!.n).to.equal(keys[0].n);
      expect(manager.getPrivateJWK(keys[1].kid)!.n).to.equal(keys[1].n);
    });

    it('encrypts and decrypts using a generated kid', async () => {
      const manager = await createJWKManager();
      await manager.addKey();
      const { kid } = manager.getPublicJWKS().keys[0];
      const message = JSON.stringify({ generated: true });

      const token = await manager.encrypt(kid, Buffer.from(message, 'utf8'));
      const { payload } = await manager.decrypt(token);

      expect(payload.toString('utf8')).to.equal(message);
    });
  });

  describe('JWK Encrypt/Decrypt', () => {
    const originalInput = JSON.stringify({ test: 'hello' });
    const inputBuffer = Buffer.from(originalInput);
    let encryptedMessage: string;

    it('encrypts Buffer input with public key set', async () => {
      const manager = await createJWKManager(publicJWKS);
      encryptedMessage = await manager.encrypt('KIBANA', inputBuffer);
      expect(encryptedMessage).to.be.a('string');
    });
    it('cannot decrypt messages using public key set', async () => {
      const manager = await createJWKManager(publicJWKS);
      let errorMessage = '';
      try {
        await manager.decrypt(encryptedMessage);
      } catch (err) {
        errorMessage = (err as Error).toString();
      }
      expect(errorMessage).to.equal('Error: no key found');
    });
    it('decrypts messages using private key set', async () => {
      const manager = await createJWKManager(privateJWKS);
      const { payload: messageBuffer } = await manager.decrypt(encryptedMessage);
      const messageObject = messageBuffer.toString();
      expect(messageObject).to.equal(originalInput);
    });
    it('returns JWKDecryptResult contract', async () => {
      const manager = await createJWKManager(privateJWKS);
      const jwkDecryptResult = await manager.decrypt(encryptedMessage);
      expect(jwkDecryptResult.header).to.eql({
        zip: 'DEF',
        enc: 'A128CBC-HS256',
        alg: 'RSA-OAEP-256',
        kid: 'KIBANA',
      });
      expect(jwkDecryptResult.protected).to.eql(['zip', 'enc', 'alg', 'kid']);
      expect(Buffer.isBuffer(jwkDecryptResult.plaintext)).to.equal(true);
      expect(Buffer.isBuffer(jwkDecryptResult.payload)).to.equal(true);
      const publicJwk = manager.getPublicJWK('KIBANA')!;
      expect(jwkDecryptResult.key).to.eql({
        kty: publicJwk.kty,
        kid: publicJwk.kid,
        use: publicJwk.use,
        alg: publicJwk.alg,
        length: Buffer.from(publicJwk.n, 'base64url').length * 8,
      });
    });
    it('cannot decrypt messages not encrypted with matching keys', async () => {
      const unworldlyManager = await createJWKManager();
      await unworldlyManager.addKey('KIBANA_7.0');
      const undecryptableMessage = await unworldlyManager.encrypt('KIBANA_7.0', inputBuffer);
      const manager = await createJWKManager(privateJWKS);

      let errorMessage = '';
      try {
        await manager.decrypt(undecryptableMessage);
      } catch (err) {
        errorMessage = (err as Error).toString();
      }
      expect(errorMessage).to.equal('Error: no key found');
    });
  });
});
