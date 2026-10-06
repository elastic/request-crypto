// Phase P0, optional: encrypt against the *real* public keys published to senders — Kibana's
// telemetry_jwks.ts (kibana1, kibana_dev1), stamped alg: "RSA-OAEP".
//
// Encryption only. The private halves live with @elastic/platform-analytics, so nothing here can
// decrypt; what this proves is that the production public keys import cleanly and wrap with
// RSA-OAEP-256 without being rotated or re-published.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequestEncryptor, KEY_WRAP_ALGORITHM } from '@elastic/request-crypto';
import shared from './_shared.cjs';

const { parseArgs, keyWrapFromBody, buildPayload } = shared;
const args = parseArgs(process.argv.slice(2));
const jwks = JSON.parse(fs.readFileSync(args.jwks, 'utf8'));
const payload = buildPayload(args);

const encryptor = await createRequestEncryptor(jwks);
const perKid = {};
for (const key of jwks.keys) {
  const body = await encryptor.encrypt(key.kid, payload);
  const alg = keyWrapFromBody(body);
  assert.equal(alg, KEY_WRAP_ALGORITHM, `${key.kid} wrapped with ${alg}`);
  perKid[key.kid] = { publishedAlg: key.alg, emittedAlg: alg, bytes: body.length };
}

process.stdout.write(`${JSON.stringify({ perKid })}\n`);
