import * as crypto from 'crypto';
import { promisify } from 'util'
import { checkCompatiblity } from './util'

const KEY_LENGTH_IN_BYTES = 32;
function getPairOptions(passphrase: string): crypto.RSAKeyPairOptions<'pem', 'pem'> {
  return {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase,
    }
  }
}

export
function generateKeyPairSync(passphrase: string): crypto.KeyPairSyncResult<string, string> {
  checkCompatiblity();
  const pairOptions = getPairOptions(passphrase);
  return crypto.generateKeyPairSync('rsa', pairOptions);
}

export
function generateKeyPair(passphrase: string): Promise<crypto.KeyPairSyncResult<string, string>> {
  checkCompatiblity();
  const generateKeyPairAsync = promisify(crypto.generateKeyPair)
  const pairOptions = getPairOptions(passphrase);
  return generateKeyPairAsync('rsa', pairOptions);
}

export
function generatePassphrase(): string {
  return crypto.randomBytes(KEY_LENGTH_IN_BYTES).toString('base64');
}