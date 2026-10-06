// An upgraded sender (what Kibana becomes at phase P3): request-crypto v3 from the packed tarball.
// It wraps with RSA-OAEP-256 even though the JWKS it is given is stamped alg: "RSA-OAEP", which is
// exactly what the keys shipped with Kibana look like today.

import fs from 'node:fs';
import { createRequestEncryptor } from '@elastic/request-crypto';
import shared from './_shared.cjs';

const { parseArgs, driveSender, buildPayload, sha256, keyWrapFromBody } = shared;
const args = parseArgs(process.argv.slice(2));
const senderJWKS = JSON.parse(fs.readFileSync(args.jwks, 'utf8'));
const encryptor = await createRequestEncryptor(senderJWKS);

if (args['emit-only']) {
  // Used by the artifact checks: produce one body without needing a receiver.
  const payload = buildPayload(args);
  const kid = String(args.kids).split(',')[0];
  const body = await encryptor.encrypt(kid, payload);
  process.stdout.write(
    `${JSON.stringify({ body, sha256: sha256(JSON.stringify(payload)), alg: keyWrapFromBody(body) })}\n`
  );
} else {
  const summary = await driveSender({
    label: 'sender-v3',
    args,
    encrypt: (kid, payload) => encryptor.encrypt(kid, payload),
  });
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}
