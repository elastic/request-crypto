import * as jose from 'node-jose';
import { SignedPublicJWK } from '../src/index';
import { createJWKManager, JWKManager } from '../src/jwk';

import { privateJWKS } from './fixture/private_jwks';
import { privatePOPJWKS } from './fixture/private_pop_jwks';
import { publicJWKS } from './fixture/public_jwks';
import { publicPOPKey } from './fixture/public_pop_jwks';

const mockJWK = Object.assign({}, jose.JWK, {
  createKey(type: any, modulus: any, config: any) {
    // override modulus bit size for faster tests.
    return jose.JWK.createKey(type, 1024, config);
  },
});

describe('JSON Web Keys Manager', () => {
  describe('JWKS', () => {
    it('creates an empty key set', async () => {
      const manager = await createJWKManager(undefined, mockJWK);
      const jwks = manager.getPrivateJWKS();

      expect(jwks).to.eql({ keys: [] });
    });
    it('prepopulates public key sets', async () => {
      const manager = await createJWKManager(publicJWKS, mockJWK);
      expect(manager.getPrivateJWKS()).to.eql(publicJWKS);
      expect(manager.getPublicJWKS()).to.eql(publicJWKS);
    });
    it('prepopulates private key sets', async () => {
      const manager = await createJWKManager(privateJWKS, mockJWK);
      const publicUJWKS = {
        ...publicJWKS,
        keys: publicJWKS.keys.map((key: SignedPublicJWK) => {
          const { cnf, ...publicJWK } = key;
          return publicJWK;
        }),
      };
      expect(manager.getPrivateJWKS()).to.eql(privateJWKS);
      expect(manager.getPublicJWKS()).to.eql(publicUJWKS);
    });
    it('adds a new key to the set', async () => {
      const manager = await createJWKManager(undefined, mockJWK);
      await manager.addKey('KIBANA_7.0');
      const { keys } = manager.getPrivateJWKS();
      expect(keys).to.have.length(1);
    });
  });

  describe('Encryption / Decryption', () => {
    const originalInput = JSON.stringify({ a: 1 });
    const inputBuffer = Buffer.from(originalInput, 'utf8');
    let encryptedMessage: string;

    it('encrypts Buffer input with public key set', async () => {
      const manager = await createJWKManager(publicJWKS, mockJWK);
      encryptedMessage = await manager.encrypt('KIBANA_6.7', inputBuffer);
      expect(encryptedMessage).to.be.a('string');
    });
    it('cannot decrypt messages using public key set', async () => {
      const manager = await createJWKManager(publicJWKS, mockJWK);
      let errorMessage = '';
      try {
        await manager.decrypt(encryptedMessage);
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.equal('Error: no key found');
    });
    it('decrypts messages using private key set', async () => {
      const manager = await createJWKManager(privateJWKS, mockJWK);
      const messageBuffer = await manager.decrypt(encryptedMessage);
      const messageObject = messageBuffer.toString();
      expect(messageObject).to.equal(originalInput);
    });
    it('cannot decrypt messages not encrypted with matching keys', async () => {
      const unworldlyManager = await createJWKManager(undefined, mockJWK);
      await unworldlyManager.addKey('KIBANA_7.0');
      const undecryptableMessage = await unworldlyManager.encrypt('KIBANA_7.0', inputBuffer);
      const manager = await createJWKManager(privateJWKS, mockJWK);

      let errorMessage = '';
      try {
        await manager.decrypt(undecryptableMessage);
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.equal('Error: no key found');
    });
  });
});
