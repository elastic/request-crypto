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

  describe('Encryption / Decryption', () => {
    const originalInput = JSON.stringify({ a: 1 });
    const inputBuffer = Buffer.from(originalInput, 'utf8');
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
        enc: 'A128CBC-HS256',
        alg: 'RSA-OAEP',
        kid: 'KIBANA',
      });
      expect(jwkDecryptResult.protected).to.have.members(['enc', 'alg', 'kid']);
      expect(Buffer.isBuffer(jwkDecryptResult.plaintext)).to.equal(true);
      expect(Buffer.isBuffer(jwkDecryptResult.payload)).to.equal(true);
      const { kty, kid, use, alg } = manager.getPublicJWK('KIBANA')!;
      expect(jwkDecryptResult.key).to.eql({ kty, kid, use, alg });
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
