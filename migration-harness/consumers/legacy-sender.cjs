'use strict';

// An un-upgraded sender: the real @elastic/request-crypto 2.0.4 from the npm registry, CommonJS,
// backed by node-jose. This is not a simulation of the old path — it is the old path.
//
// It wraps with RSA-OAEP because node-jose follows the JWKS "alg" member, and the JWKS the harness
// hands it is stamped alg: "RSA-OAEP", like the keys Kibana ships today.

const fs = require('node:fs');
const { createRequestEncryptor } = require('@elastic/request-crypto');
const { parseArgs, driveSender, buildPayload, sha256, keyWrapFromBody } = require('./_shared.cjs');

const args = parseArgs(process.argv.slice(2));

(async () => {
  const senderJWKS = JSON.parse(fs.readFileSync(args.jwks, 'utf8'));
  const encryptor = await createRequestEncryptor(senderJWKS);

  if (args['emit-only']) {
    const payload = buildPayload(args);
    const kid = String(args.kids).split(',')[0];
    const body = await encryptor.encrypt(kid, payload);
    process.stdout.write(
      `${JSON.stringify({
        body,
        sha256: sha256(JSON.stringify(payload)),
        alg: keyWrapFromBody(body),
      })}\n`
    );
    return;
  }

  const summary = await driveSender({
    label: 'sender-2.0.4',
    args,
    encrypt: (kid, payload) => encryptor.encrypt(kid, payload),
  });
  process.stdout.write(`${JSON.stringify(summary)}\n`);
})().catch(err => {
  process.stderr.write(`${err.stack}\n`);
  process.exit(1);
});
