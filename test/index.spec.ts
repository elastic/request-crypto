/// <reference path="typings/global.d.ts" />

import { decryptPayload, encryptPayload } from '../src';

import { readFile } from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { jwksPairs } from './fixture/full_jwks';
import { wellKnowns } from './fixture/well_knowns';

const readFileAsync = promisify(readFile);

const largePayloadPath = path.join(__dirname, 'fixture/large_payload.json');
const encryptedLargePayloadPath = path.join(__dirname, 'fixture/large_payload.base64.enc');
const encryptedLargePayloadKeyPath = path.join(__dirname, 'fixture/large_payload_key.base64.enc');

const smallPayloadPath = path.join(__dirname, 'fixture/small_payload.json');
const encryptedSmallPayloadPath = path.join(__dirname, 'fixture/small_payload.base64.enc');
const encryptedSmallPayloadKeyPath = path.join(__dirname, 'fixture/small_payload_key.base64.enc');

describe('request crypto', () => {
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

  describe('encryptPayload', () => {
    it('encrypts small payload with public key', async () => {
      const result = await encryptPayload(smallPayload, 'KIBANA_6.7', wellKnowns);
      expect(result).to.have.all.keys(['payload', 'key']);
    });
    it('encrypts large payload with public key', async () => {
      const result = await encryptPayload(largePayload, 'KIBANA_6.7', wellKnowns);
      expect(result).to.have.all.keys(['payload', 'key']);
    });
  });

  describe('decryptPayload', () => {
    it('decrypts small payload with private key', async () => {
      const decryptedPayload = await decryptPayload(
        encryptedSmallPayload,
        encryptedKeyForSmall,
        jwksPairs
      );
      expect(decryptedPayload).to.eql(smallPayload);
    });
    it('decrypts large payload with private key', async () => {
      const decryptedPayload = await decryptPayload(
        encryptedLargePayload,
        encryptedKeyForLarge,
        jwksPairs
      );
      expect(decryptedPayload).to.eql(largePayload);
    });
  });
});
