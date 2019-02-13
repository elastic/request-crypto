import { readFile } from 'fs';
import * as path from 'path';
import { promisify } from 'util';

import {
  createRequestDecryptor,
  createRequestEncryptor,
  Decryptor,
  Encryptor,
} from '../src/request';

import { privateJWKS } from './fixture/private_jwks';
import { publicJWKS } from './fixture/public_jwks';

import { JWKS, PrivateJWK, PublicJWK, PublicJWKS } from '../src';
import { privateComponents, publicComponents } from './helpers';

const readFileAsync = promisify(readFile);

const largePayloadPath = path.join(__dirname, 'fixture/large_payload.json');
const encryptedLargePayloadPath = path.join(__dirname, 'fixture/large_payload.base64.enc');
const encryptedLargePayloadKeyPath = path.join(__dirname, 'fixture/large_payload_key.base64.enc');

const smallPayloadPath = path.join(__dirname, 'fixture/small_payload.json');
const encryptedSmallPayloadPath = path.join(__dirname, 'fixture/small_payload.base64.enc');
const encryptedSmallPayloadKeyPath = path.join(__dirname, 'fixture/small_payload_key.base64.enc');

describe('Request Crypto', () => {
  function modifyJWKS<T>(jwks: JWKS<T>, modifier: any): JWKS<T> {
    return {
      ...jwks,
      keys: jwks.keys.map(modifier),
    };
  }

  let smallPayload: Partial<object>;
  let encryptedSmallPayload: string;
  let encryptedKeyForSmall: string;

  let largePayload: Partial<object>;
  let encryptedLargePayload: string;
  let encryptedKeyForLarge: string;

  before(async () => {
    smallPayload = JSON.parse(await readFileAsync(smallPayloadPath, 'utf-8'));
    encryptedKeyForSmall = await readFileAsync(encryptedSmallPayloadKeyPath, 'utf-8');
    encryptedSmallPayload = await readFileAsync(encryptedSmallPayloadPath, 'utf-8');

    largePayload = JSON.parse(await readFileAsync(largePayloadPath, 'utf-8'));
    encryptedKeyForLarge = await readFileAsync(encryptedLargePayloadKeyPath, 'utf-8');
    encryptedLargePayload = await readFileAsync(encryptedLargePayloadPath, 'utf-8');
  });

  describe('Request Decryptor', () => {
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
    describe('Decryption', async () => {
      it('decrypts small payload with private key', async () => {
        const decryptor = await createRequestDecryptor(privateJWKS);
        const decryptedPayload = await decryptor.decryptPayload(
          encryptedSmallPayload,
          encryptedKeyForSmall
        );
        expect(decryptedPayload).to.eql(smallPayload);
      });
      it('decrypts large payload with private key', async () => {
        const decryptor = await createRequestDecryptor(privateJWKS);
        const decryptedPayload = await decryptor.decryptPayload(
          encryptedLargePayload,
          encryptedKeyForLarge
        );
        expect(decryptedPayload).to.eql(largePayload);
      });
    });
  });

  describe('Request Encryptor', () => {
    let encryptor: Encryptor;
    before(async () => {
      encryptor = await createRequestEncryptor(publicJWKS);
    })
    it('fails to encrypt using unknown kid', async () => {
      let errorMessage: string;
      try {
        const encryptionOutput = await encryptor.encrypt('missingKID', smallPayload);
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.eql('Error: Missing kid (missingKID).');
    });

    it('encrypts small payload', async () => {
      const encryptionOutput = await encryptor.encrypt('KIBANA_6.7', smallPayload);
      expect(encryptionOutput).to.have.keys('key', 'payload');
    });

    it('encrypts large payload', async () => {
      const encryptionOutput = await encryptor.encrypt('KIBANA_6.7', largePayload);
      expect(encryptionOutput).to.have.keys('key', 'payload');
    });
  });
});
