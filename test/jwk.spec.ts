/// <reference path="typings/global.d.ts" />

import { wellKnowns } from './fixture/well_knowns';
import { jwksPairs } from './fixture/full_jwks';

import {
  createJWKManager,
} from '../src/jwk';
import { JWK } from 'node-jose'

describe("JSON Web Keys Manager", () => {
  let originalCreateKey: any;

  before(() => {
    originalCreateKey = JWK.createKey;
    createJWKManager.JWK.createKey = (type: any, modulus: any, config: any) => {
      // override modulus bit size for faster tests.
      return originalCreateKey(type, 1024, config);
    }
  })

  describe("JWKS", () => {
    it("creates an empty key set", async () => {
      const manager = await createJWKManager();
      const { keys } = manager.getFullJWKS();
      
      expect(keys).to.be.an('array');
      expect(keys).to.be.empty;
    })
    it("creates a prepopulated key set", async () => {
      const manager = await createJWKManager(wellKnowns);
      const jwks = manager.getFullJWKS();
      expect(jwks).to.eql(wellKnowns);
    })
    it("adds a new key to the set", async () => {
      const manager = await createJWKManager();
      await manager.addKey('KIBANA_7.0');
      const { keys } = manager.getFullJWKS();
      expect(keys).to.have.length(1);      
    })
  })

  describe('Encryption / Decryption', () => {
    const originalMessage = Buffer.from(JSON.stringify({a: 1}), 'utf8').toString('base64');
    let encryptedMessage: string;

    it('encrypts string input with public key set', async () => {
      const manager = await createJWKManager(wellKnowns);
      encryptedMessage = await manager.encrypt('KIBANA_6.7', originalMessage);
      expect(encryptedMessage).to.be.a('string');
      expect(encryptedMessage).to.not.be.empty;
    })
    it('encrypts Buffer input with public key set', async () => {
      const manager = await createJWKManager(wellKnowns);
      const bufferInput = Buffer.from(originalMessage, 'base64');
      const encryptedMessage2 = await manager.encrypt('KIBANA_6.7', bufferInput);
      expect(encryptedMessage2).to.be.a('string');
      expect(encryptedMessage2).to.not.be.empty;
    })

    it('cannot decrypt messages using public key set', async () => {
      const manager = await createJWKManager(wellKnowns);
      let errorMessage = '';
      try {
        await manager.decrypt(encryptedMessage);
      } catch(err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.equal('Error: no key found');
    })
    it('decrypts messages using private key set', async () => {
      const manager = await createJWKManager(jwksPairs);
      const message = await manager.decrypt(encryptedMessage);
      expect(message).to.equal(originalMessage);
    })
    it('cannot decrypt messages not encrypted with matching keys', async () => {
      const unworldlyManager = await createJWKManager();
      await unworldlyManager.addKey('KIBANA_7.0');
      const undecryptableMessage = await unworldlyManager.encrypt('KIBANA_7.0', originalMessage);
      const manager = await createJWKManager(jwksPairs);

      let errorMessage = '';
      try {
        await manager.decrypt(undecryptableMessage)
      } catch(err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.equal('Error: no key found');
    })
  })

  after(() => {
    createJWKManager.JWK.createKey = originalCreateKey;
  })
})