/// <reference path="typings/global.d.ts" />

import {
  encryptPayload,
  decryptPayload,
} from '../src'

import { promisify } from 'util'
import { readFile } from 'fs'
import * as path from 'path'

const readFileAsync = promisify(readFile)
const largePayloadPath = path.join(__dirname, 'fixture/large_payload.json');
const smallPayloadPath = path.join(__dirname, 'fixture/small_payload.json');
const privateKeyPath = path.join(__dirname, 'fixture/private_key.pem');
const publicKeyPath = path.join(__dirname, 'fixture/public_key.pem');

describe('request crypto', () => {
  let largePayload: Partial<object>;
  let smallPayload: Partial<object>;
  let publicKey: string;
  let privateKey: any;

  let encryptedKeyForSmall: string
  let encryptedKeyForLarge: string
  let encryptedLargePayload: string
  let encryptedSmallPayload: string

  before(async () => {
    publicKey = await readFileAsync(publicKeyPath, 'utf-8');
    privateKey = { key: await readFileAsync(privateKeyPath, 'utf-8'), passphrase: 'testtest' };
    largePayload = JSON.parse(await readFileAsync(largePayloadPath, 'utf-8'));
    smallPayload = JSON.parse(await readFileAsync(smallPayloadPath, 'utf-8'));
  })

  describe('encryptPayload', () => {
    it('encrypts small payload with public key', async () => {
      const result = await encryptPayload(smallPayload, publicKey)
      encryptedKeyForSmall = result.key;
      encryptedSmallPayload = result.payload;

      expect(result).to.have.all.keys(['payload', 'key'])
    })
    it('encrypts large payload with public key', async () => {
      const result = await encryptPayload(largePayload, publicKey)
      encryptedKeyForLarge = result.key;
      encryptedLargePayload = result.payload;

      expect(result).to.have.all.keys(['payload', 'key'])
    })
  })

  describe('decryptPayload', () => {
    it('decrypts small payload with private key', async () => {
      const decryptedPayload = await decryptPayload(encryptedSmallPayload, encryptedKeyForSmall, privateKey);
      expect(decryptedPayload).to.eql(smallPayload)
    });
    it('decrypts large payload with private key', async () => {
      const decryptedPayload = await decryptPayload(encryptedLargePayload, encryptedKeyForLarge, privateKey);
      expect(decryptedPayload).to.eql(largePayload)
    })
  });

})