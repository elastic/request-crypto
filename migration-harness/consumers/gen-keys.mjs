// Generates the key material the harness runs against, using the packed v3 build.
//
// Two JWKS come out of this, and the difference between them is the whole point:
//
//   private.json     — what the receiver holds. Keys are stamped alg: "RSA-OAEP-256", because v3
//                      generates them that way.
//   sender-jwks.json — what senders are given. Identical public keys, but stamped alg: "RSA-OAEP",
//                      which is the shape of every public key published to senders today
//                      (see Kibana's telemetry_jwks.ts).
//
// A 2.0.4 sender reading sender-jwks.json therefore wraps with RSA-OAEP, and a v3 sender reading
// the very same file wraps with RSA-OAEP-256, because v3 ignores the member. That is production
// during phases P3–P4, reproduced without touching a single real key.

import fs from 'node:fs';
import path from 'node:path';
import { createJWKManager, LEGACY_KEY_WRAP_ALGORITHM } from '@elastic/request-crypto';
import shared from './_shared.cjs';

const { parseArgs } = shared;
const args = parseArgs(process.argv.slice(2));
const outDir = args.out;
const kids = String(args.kids).split(',');

const manager = await createJWKManager();
for (const kid of kids) {
  await manager.addKey(kid);
}

const privateJWKS = manager.getPrivateJWKS();
const publicJWKS = manager.getPublicJWKS();
const senderJWKS = {
  keys: publicJWKS.keys.map(key => ({ ...key, alg: LEGACY_KEY_WRAP_ALGORITHM })),
};

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'private.json'), JSON.stringify(privateJWKS, null, 2));
fs.writeFileSync(path.join(outDir, 'public.json'), JSON.stringify(publicJWKS, null, 2));
fs.writeFileSync(path.join(outDir, 'sender-jwks.json'), JSON.stringify(senderJWKS, null, 2));

process.stdout.write(
  `${JSON.stringify({
    kids: privateJWKS.keys.map(key => key.kid),
    privateAlgs: privateJWKS.keys.map(key => key.alg),
    senderAlgs: senderJWKS.keys.map(key => key.alg),
  })}\n`
);
