'use strict';

// Phase P0: how a CommonJS consumer reaches an ESM-only package. The receiving telemetry service is
// the consumer that matters here, so both routes are checked:
//
//   require('@elastic/request-crypto')       — works on Node >= 20.19 / >= 22.12 (require(esm)).
//   await import('@elastic/request-crypto')  — the documented route, must work everywhere.
//
// A failing `require` is reported, not fatal; a failing dynamic import is fatal.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { parseArgs, sha256, keyWrapFromBody, buildPayload } = require('./_shared.cjs');

const args = parseArgs(process.argv.slice(2));

(async () => {
  const result = { node: process.version, require: null, dynamicImport: null };

  try {
    const required = require('@elastic/request-crypto');
    assert.equal(typeof required.createRequestDecryptor, 'function');
    result.require = { ok: true, keyWrapAlgorithm: required.KEY_WRAP_ALGORITHM };
  } catch (err) {
    result.require = { ok: false, code: err.code, message: err.message };
  }

  const imported = await import('@elastic/request-crypto');
  const privateJWKS = JSON.parse(fs.readFileSync(args['private-jwks'], 'utf8'));
  const senderJWKS = JSON.parse(fs.readFileSync(args['sender-jwks'], 'utf8'));
  const payload = buildPayload(args);

  const encryptor = await imported.createRequestEncryptor(senderJWKS);
  const decryptor = await imported.createRequestDecryptor(privateJWKS);
  const body = await encryptor.encrypt(senderJWKS.keys[0].kid, payload);
  assert.equal(keyWrapFromBody(body), imported.KEY_WRAP_ALGORITHM);
  assert.equal(sha256(JSON.stringify(await decryptor.decrypt(body))), sha256(JSON.stringify(payload)));
  result.dynamicImport = { ok: true, keyWrapAlgorithm: imported.KEY_WRAP_ALGORITHM, roundTrip: true };

  process.stdout.write(`${JSON.stringify(result)}\n`);
})().catch(err => {
  process.stderr.write(`${err.stack}\n`);
  process.exit(1);
});
