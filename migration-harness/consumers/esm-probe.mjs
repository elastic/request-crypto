// Phase P0: exercises the packed artifact the way a consumer would — through the package's exports
// map, not the source tree. Also decrypts a body produced by the real 2.0.4, so the cross-version
// claim is checked against the thing that would actually be published.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as requestCrypto from '@elastic/request-crypto';
import shared from './_shared.cjs';

const { parseArgs, sha256, keyWrapFromBody, buildPayload } = shared;
const args = parseArgs(process.argv.slice(2));

const expectedExports = [
  'createRequestEncryptor',
  'createRequestDecryptor',
  'createJWKManager',
  'createJWKSManager',
  'createJWKS',
  'packBody',
  'unpackBody',
  'generatePassphrase',
  'KeyStore',
  'KEY_WRAP_ALGORITHM',
  'LEGACY_KEY_WRAP_ALGORITHM',
  'SUPPORTED_KEY_WRAP_ALGORITHMS',
  'CONTENT_ENCRYPTION_ALGORITHM',
  'MAX_DECOMPRESSED_LENGTH',
  'RSA_ALGORITHM',
  'ENC_MODULUS',
];
const missing = expectedExports.filter(name => !(name in requestCrypto));
assert.deepEqual(missing, [], `missing exports: ${missing.join(', ')}`);

const privateJWKS = JSON.parse(fs.readFileSync(args['private-jwks'], 'utf8'));
const senderJWKS = JSON.parse(fs.readFileSync(args['sender-jwks'], 'utf8'));
const payload = buildPayload(args);
const kid = senderJWKS.keys[0].kid;

const seen = [];
const encryptor = await requestCrypto.createRequestEncryptor(senderJWKS);
const decryptor = await requestCrypto.createRequestDecryptor(privateJWKS, {
  onKeyWrap: info => seen.push(info),
});

// A sender-facing JWK stamped with the legacy algorithm must still produce RSA-OAEP-256.
const body = await encryptor.encrypt(kid, payload);
const emittedAlg = keyWrapFromBody(body);
assert.equal(emittedAlg, requestCrypto.KEY_WRAP_ALGORITHM);
assert.equal(sha256(JSON.stringify(await decryptor.decrypt(body))), sha256(JSON.stringify(payload)));
assert.equal(seen.at(-1).legacy, false);

// And a body from the real 2.0.4 must still decrypt.
let legacy = null;
if (args['legacy-body-file']) {
  const emitted = JSON.parse(fs.readFileSync(args['legacy-body-file'], 'utf8'));
  const decrypted = await decryptor.decrypt(emitted.body);
  assert.equal(sha256(JSON.stringify(decrypted)), emitted.sha256, 'legacy payload did not survive');
  assert.equal(seen.at(-1).alg, requestCrypto.LEGACY_KEY_WRAP_ALGORITHM);
  assert.equal(seen.at(-1).legacy, true);
  legacy = { alg: emitted.alg, decrypted: true };
}

process.stdout.write(
  `${JSON.stringify({
    node: process.version,
    exports: 'complete',
    keyWrapAlgorithm: requestCrypto.KEY_WRAP_ALGORITHM,
    supported: requestCrypto.SUPPORTED_KEY_WRAP_ALGORITHMS,
    maxDecompressedLength: requestCrypto.MAX_DECOMPRESSED_LENGTH,
    emittedAlg,
    roundTrip: true,
    legacy,
  })}\n`
);
