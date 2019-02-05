import { readFile } from 'fs';
import * as path from 'path';
import { promisify } from 'util';

import {
  createRequestDecryptor,
  createRequestEncryptor,
  Decryptor,
  Encryptor,
} from '../src/request';

import { identity } from './fixture/identity';
import { mismatchPublicJWKS } from './fixture/mismatch_public_jwks';
import { privateJWKS } from './fixture/private_jwks';

import { privatePOPJWKS } from './fixture/private_pop_jwks';
import { publicJWKS } from './fixture/public_jwks';

import { JWKS, PrivateJWK, PublicJWKS, SignedPublicJWK, SignedPublicJWKS } from '../src';
import { privateComponents, signedPublicComponents } from './helpers';

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
      it('provides a list of well knowns signed with popKey', async () => {
        const decryptor = await createRequestDecryptor(privateJWKS);
        const wellKnowns = await decryptor.getWellKnowns(identity);
        wellKnowns.keys.forEach((key: SignedPublicJWK) => {
          expect(key).to.have.keys(signedPublicComponents);
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

    it('creates new POP JWKS', async () => {
      const emptyEncryptor = await createRequestEncryptor();
      await emptyEncryptor.addPOPJWK();
      const popJWKS = emptyEncryptor.getPrivatePOPJWKS();
      expect(popJWKS).to.have.keys(['keys']);
      popJWKS.keys.forEach((key: PrivateJWK) => {
        expect(key).to.have.keys(privateComponents);
      });
    });
    it('prepopulates pop JWKS', async () => {
      encryptor = await createRequestEncryptor(privatePOPJWKS);
      const popJWKS = encryptor.getPrivatePOPJWKS();
      expect(popJWKS).to.eql(privatePOPJWKS);
    });
    it('gets POP JWK identity', () => {
      const createdIdentity = encryptor.getIdentity();
      expect(createdIdentity).to.eql(identity);
    });
    it('fails to encrypt using unkown kid', async () => {
      let errorMessage: string;
      try {
        const encryptionOutput = await encryptor.verifyAndEncrypt(
          smallPayload,
          'missingKID',
          publicJWKS
        );
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.eql('Error: Missing kid.');
    });
    it('fails on non-matching signature confirmation', async () => {
      let errorMessage: string;
      try {
        const encryptionOutput = await encryptor.verifyAndEncrypt(
          smallPayload,
          'KIBANA_6.7',
          mismatchPublicJWKS
        );
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.eql('Error: no key found');
    });
    it('fails on invalid signature confirmation', async () => {
      let errorMessage: string;
      const corruptedPublicJWKS = modifyJWKS(publicJWKS, (signedKey: SignedPublicJWK) => ({
        ...signedKey,
        cnf:
          'eyJ6aXAiOiJERUYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJFTlNmMndSRVhVVkM3OEgySk1fcDkxRWNZVWJCWTJ3QjZGVW92Q0pDVlJJIn0.Sy3j2gbqmVjLXnv8_4CSiKSZqwHnGMdkviZBRUesh058A1MgVZRoZyDaR7QSTRSGYilaYonLnudJQZ6X2DE8zNcdpH_eWTSU5olrr2izMKqr92EV4rNSOBNliYQAGAWB3UonoYJyiUVx0AFnHzxj0rbl86iz2ZTDlVAcGRuVVbs.FYkMyrY51VARUqC1CC26Qg.KknWxyyYGxw_dyw51u9rg6knpH5cKGVnAwdyMmoSzE3fO2XxFs-ku2JuQgzCxKJV.pdm5Z9GqyPBwPHcjZuKWTw',
      }));

      try {
        const encryptionOutput = await encryptor.verifyAndEncrypt(
          smallPayload,
          'KIBANA_6.7',
          corruptedPublicJWKS
        );
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.eql('Error: no key found');
    });
    it('fails on missing cnf', async () => {
      let errorMessage: string;
      const corruptedPublicJWKS = modifyJWKS(publicJWKS, (signedKey: SignedPublicJWK) => {
        const { cnf, ...uJWK } = signedKey;
        return uJWK;
      });

      try {
        const encryptionOutput = await encryptor.verifyAndEncrypt(
          smallPayload,
          'KIBANA_6.7',
          corruptedPublicJWKS as SignedPublicJWKS
        );
      } catch (err) {
        errorMessage = err.toString();
      }
      expect(errorMessage).to.eql('Error: Invalid Confirmation Signature.');
    });
    it('encrypts small payload', async () => {
      const encryptionOutput = await encryptor.verifyAndEncrypt(
        smallPayload,
        'KIBANA_6.7',
        publicJWKS
      );

      expect(encryptionOutput).to.have.keys('key', 'payload');
    });
    it('encrypts large payload', async () => {
      const encryptionOutput = await encryptor.verifyAndEncrypt(
        largePayload,
        'KIBANA_6.7',
        publicJWKS
      );
      expect(encryptionOutput).to.have.keys('key', 'payload');
    });
  });
});
