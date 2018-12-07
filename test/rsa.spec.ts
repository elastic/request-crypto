/// <reference path="typings/global.d.ts" />

import { makeRSACryptoWith } from '../src/rsa'
import { readFile } from 'fs'
import * as path from 'path'
import { promisify } from 'util'

const readFileAsync = promisify(readFile)

const privateKeyPath = path.join(__dirname, 'fixture/private_key.pem');
const publicKeyPath = path.join(__dirname, 'fixture/public_key.pem');
const encryptedRSAPath = path.join(__dirname, 'fixture/somekey.base64.enc');

describe('RSA', () => {
  let publicKey: string;
  let encryptedRSA: string;
  let privateKey: string;
  before(async () => {
    publicKey = await readFileAsync(publicKeyPath, 'utf-8');
    encryptedRSA = await readFileAsync(encryptedRSAPath, 'utf-8');
    privateKey = await readFileAsync(privateKeyPath, 'utf-8');
  })

  describe('publicEncrypt', () => {
    it('fails if no public key is passed to the module', () => {
      const { publicEncrypt } = makeRSACryptoWith({});
      const publicEncryptor = () => publicEncrypt("somekey")
      expect(publicEncryptor).to.throw();
    })
    it('encrypts string when publicKey is sent as a string', () => {
      const { publicEncrypt } = makeRSACryptoWith({ publicKey });
      const encryptedKey = publicEncrypt("somekey");
      expect(Buffer.isBuffer(encryptedKey)).to.be.true
    })
    it('encrypts string when publicKey is sent as a object', () => {
      const { publicEncrypt } = makeRSACryptoWith({ publicKey: { key: publicKey } });
      const encryptedKey = publicEncrypt("somekey");
      expect(Buffer.isBuffer(encryptedKey)).to.be.true
    })
  })

  describe('privateDecrypt', () => {
    it('fails if no private key is passed to the module', () => {
      const { privateDecrypt } = makeRSACryptoWith({});
      const privateDecryptor = () => privateDecrypt(encryptedRSA);
      expect(privateDecryptor).to.throw();
    })
    it('decrypts base64 encrypted data from private/public keys', () => {
      const { privateDecrypt } = makeRSACryptoWith({ privateKey: {
        key: privateKey,
        passphrase: 'testtest'
      }});
      const data = privateDecrypt(encryptedRSA).toString();
      expect(data).to.eql('somekey');
    })
  })

})
