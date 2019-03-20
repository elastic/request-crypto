import { readFile } from 'fs';
import * as path from 'path';
import { promisify } from 'util';

import { createRequestDecryptor, createRequestEncryptor } from '../src/request';

import { privateJWKS } from './fixture/private_jwks';
import { publicJWKS } from './fixture/public_jwks';

import { JWKS, PublicJWK } from '../src';
import { publicComponents } from './helpers';

import * as largePayload from './fixture/large_payload.json';
import * as smallPayload from './fixture/small_payload.json';

describe('Request Crypto', () => {
  let encryptedBodyWithSmallPayload: string;
  let encryptedBodyWithLargePayload: string;

  describe('Well Knowns', () => {
    it('provides a list of well knowns', async () => {
      const decryptor = await createRequestDecryptor(privateJWKS);
      const wellKnowns = await decryptor.getWellKnowns();
      expect(wellKnowns.keys).to.have.length(1);
      wellKnowns.keys.forEach((key: PublicJWK) => {
        expect(key).to.have.keys(publicComponents);
      });
    });
  });

  describe('Request Encryption', () => {
    it('fails to encrypt using unknown kid', async () => {
      let errorMessage: string;
      try {
        const encryptor = await createRequestEncryptor(publicJWKS);
        await encryptor.encrypt('missingKID', smallPayload);
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.eql('Error: Missing kid (missingKID).');
    });

    it('encrypts small payload', async () => {
      const encryptor = await createRequestEncryptor(publicJWKS);
      encryptedBodyWithSmallPayload = await encryptor.encrypt('KIBANA', smallPayload);
      expect(encryptedBodyWithSmallPayload).to.be.a('string');
    });

    it('encrypts large payload', async () => {
      const encryptor = await createRequestEncryptor(publicJWKS);
      encryptedBodyWithLargePayload = await encryptor.encrypt('KIBANA', largePayload);
      expect(encryptedBodyWithLargePayload).to.be.a('string');
    });
  });

  describe('Request Decryption', async () => {
    it('decrypts small payload with private key', async () => {
      const decryptor = await createRequestDecryptor(privateJWKS);
      const decryptedPayload = await decryptor.decrypt(encryptedBodyWithSmallPayload);
      expect(decryptedPayload).to.eql(smallPayload);
    });
    it('decrypts large payload with private key', async () => {
      const decryptor = await createRequestDecryptor(privateJWKS);
      const decryptedPayload = await decryptor.decrypt(encryptedBodyWithLargePayload);
      expect(decryptedPayload).to.eql(largePayload);
    });
  });
});
