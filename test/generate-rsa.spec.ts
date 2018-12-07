/// <reference path="typings/global.d.ts" />

import { generateKeyPair, generateKeyPairSync, generatePassphrase } from '../src/generate-rsa';
import { checkNodeCompatiblity } from '../src/util';

const isCompatible = (function() {
  try {
    // `crypto.generateKeyPair` is only supported after node version 10.12.0
    checkNodeCompatiblity(10.12);
    return true;
  } catch (err) {
    return false;
  }
})();

describe('generate-rsa', () => {
  let originalVersion: any;

  before(() => {
    originalVersion = Object.getOwnPropertyDescriptor(process, 'version');
  });

  describe('generatePassphrase', () => {
    it('generates a random passphrase', () => {
      const pass1 = generatePassphrase();
      const pass2 = generatePassphrase();
      expect(pass1).to.be.a('string');
      expect(pass1).to.not.equal(pass2);
    });
  });
  describe('generateKeyPair', () => {
    it('fails if not node version is not compatible', async function() {
      Object.defineProperty(process, 'version', { value: 'v8.10.0' });
      try {
        await generateKeyPair('testtest');
        throw new Error('FAIL');
      } catch (err) {
        expect(err).to.not.equal('FAIL');
      }
      Object.defineProperty(process, 'version', originalVersion);
    });

    it('generates a key pair', async function() {
      if (!isCompatible) {
        this.skip();
      }
      const keyPair = await generateKeyPair('testtest');
      expect(keyPair).to.have.keys(['publicKey', 'privateKey']);
    });
  });

  describe('generateKeyPairSync', () => {
    it('fails if not node version is not compatible', () => {
      Object.defineProperty(process, 'version', { value: 'v8.10.0' });
      const pairGenerator = () => generateKeyPairSync('testtest');
      expect(pairGenerator).to.throw();
      Object.defineProperty(process, 'version', originalVersion);
    });

    it('generates a key pair', function() {
      if (!isCompatible) {
        this.skip();
      }
      const keyPair = generateKeyPairSync('testtest');
      expect(keyPair).to.have.keys(['publicKey', 'privateKey']);
    });
  });
});
