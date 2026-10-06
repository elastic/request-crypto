# Request Cryptography

<p align="center">
  JWK+JWE with AES Encryption for Request Encrypt/decrypt
</p>

<p align="center">
  <a href="https://badge.fury.io/js/%40elastic%2Frequest-crypto"><img src="https://badge.fury.io/js/%40elastic%2Frequest-crypto.svg" alt="npm version" height="18"></a>
</p>

> **Note (v3):** This package is now **ESM-only** and requires **Node.js ≥ 20.12.0**. CJS
> consumers must switch to `await import('@elastic/request-crypto')`.
>
> The key wrap algorithm changes: encryption now uses **`RSA-OAEP-256`** (RSAES-OAEP with SHA-256
> + MGF1-SHA-256) instead of `RSA-OAEP` (SHA-1 + MGF1-SHA-1), which is not FIPS 140-3 approved.
> Decryption accepts **both**, selected per token from its protected header, so an upgraded
> receiver keeps decrypting tokens from senders that have not upgraded yet. The rest of the wire
> format — `A128CBC-HS256`, `zip:DEF`, JWE compact serialization — is unchanged from v2.
>
> **A receiver running v2 cannot decrypt `RSA-OAEP-256` tokens**, so receivers must upgrade before
> senders. See [docs/rsa-oaep-256-migration.md](docs/rsa-oaep-256-migration.md) for the rollout and
> validation plan.

### High level overview

There are 3 parts involved for JWK encryption:
- Mediator (Browser)
- Sender (Kibana server)
- Receiver (Telemetry service)

1. Mediator Requests Sender for encrypted metrics
2. Sender gathers metrics and encrypts them following these steps:
   1. Sender encrypts data with a randomly generated 32-bytes AES passphrase.
   2. Sender encrypts payload with a strong AES 256 bit key that is derived from the passphrase.
   3. Sender uses public RSA key that is shipped with Kibana to encrypt the AES key.
   4. Sender sends the Mediator the AES encrypted payload and the JWK encrypted AES key.
3. Mediator sends the encrypted payload and encrypted AES key to Receiver.
4. Receiver gets the needed data from mediators
   1. Receiver decrypts AES key using the private key that corresponds to the public key used for encryption.
   2. Receiver decrypts payload with decrypted AES key.
   3. Receiver processes payload.

### Why?

JWK are a way to pass public/private keys (RSA) in JSON format.

With RSA, the data to be encrypted is first mapped on to an integer. For
RSA to work, this integer must be smaller than the RSA modulus used. In other words,
public key cannot be used to encrypt large payloads.

The way to solve this is to encrypt the payload with a strong AES key, then encrypt the
AES key with the public key, and send that key along with the request.

RSA is almost never used for data encryption. The approach we've taken here is the common one (TLS, PGP etc do the same in principle) where a symmetric key is used for data encryption and that key is then encrypted with RSA. Size is one constraint, the other is performance as RSA is painfully slow compared to a symmetric key cipher such as AES.


### Where to put the Key?
- RSA Public Keys are distributed with the kibana distribution as a JWK.
- RSA Private Keys are kept private and must never be shared.
- The AES Passphrase will be generated on the sender's side uniquely on each request.

## Usage

Request crypto has two main servicers `Encryptor` and `Decryptor`.
`Encryptor` is used by the sending side. while `Decryptor` is used by the recieving side.



#### Sender Side (ie Kibana)

```js
import { createRequestEncryptor } from '@elastic/request-crypto';
import * as fs from 'fs';

function TelemetryEndpointRoute(req, res) {
  const metrics = await getCollectors();
  const publicEncryptionKey = await fs.readAsync('...', 'utf8');
  const requestEncryptor = await createRequestEncryptor(publicEncryptionKey);
  const version = getKibanaVersion();
  
  try {
    const encryptedPayload = await requestEncryptor.encrypt(`kibana_${version}`, metrics);
    res.end(encryptedPayload);
  } catch(err) {
    res.status(500).end(`Error: ${err}`);
  }
}
```


#### Mediator (ie browser)

```js
async function getTelemetryMetrics() {
  return fetch(server.telemetryEndpoint);
}

async function sendTelemetryMetrics() {
  const metrics = await getTelemetryMetrics();
  return fetch('https://telemetry.elastic.co/v2/xpack', {
    method: 'POST', 
    body: metrics
  });
}
```

#### Recieving side (ie Telemetry Service)

```js
import { createRequestDecryptor } from '@elastic/request-crypto';
import privateJWKS from './privateJWKS';

async function handler (event, context, callback) {
  const requestDecryptor = await createRequestDecryptor(privateJWKS);
  const decryptedPayload = await requestDecryptor.decryptPayload(event.body);

  // ... handle payload
}
```

## JWKS

Json Web Key Sets are to store multiple JWK.

#### Why Key rotation?

Having keys per use case will reduce the surface of damage in case a key compromise happens.


### Create a new keyset

```js
import { createJWKManager } from '@elastic/request-crypto';
const jwksManager = await createJWKManager();
await jwksManager.addKey(`<kid>`);
```

### Use existing keyset

```js
import { createJWKManager } from '@elastic/request-crypto';
const existingJWKS = `<fetched from fs>`
const jwksManager = await createJWKManager(existingJWKS);

// get public key components
jwksManager.getPublicJWKS();
// get full Key pairs Inlcuding private components
jwksManager.getPrivateJWKS();
```

### Getting JWK metadata from request

The method `getJWKMetadata` returns the metadata of the JWK used to encrypt the request body.

The metadata is an object including the following:
- `key`: JWK details (`kid`, `length`, `kty`, `use`, `alg`)
- `protected` an array of the member names from the "protected" member.
- `header`: an object of "protected" member key values.

```js
import { createRequestDecryptor } from '@elastic/request-crypto';
import privateJWKS from './privateJWKS';

async function handler (event, context, callback) {
  const requestDecryptor = await createRequestDecryptor(privateJWKS);
  const jwkMetadata = await requestDecryptor.getJWKMetadata(event.body);

  // ... use metadata
}
```

If the key is not in the provided JWKS the function will throw an error `Error: no key found`.

## Algorithms

| Constant | Value | Used for |
|---|---|---|
| `KEY_WRAP_ALGORITHM` | `RSA-OAEP-256` | every token this package encrypts |
| `LEGACY_KEY_WRAP_ALGORITHM` | `RSA-OAEP` | accepted when decrypting, never emitted |
| `SUPPORTED_KEY_WRAP_ALGORITHMS` | both of the above | the decrypt allowlist |
| `CONTENT_ENCRYPTION_ALGORITHM` | `A128CBC-HS256` | content encryption, pinned on both sides |
| `MAX_DECOMPRESSED_LENGTH` | `250000` | ceiling on inflating a `zip:DEF` plaintext |

Decryption is pinned to these algorithms, so a token naming anything else is rejected before any
key is used. A key's own JWK `alg` member does not affect which algorithm is used — keys are
imported for whichever algorithm is required — so public keys already published as
`alg: "RSA-OAEP"` encrypt with `RSA-OAEP-256` without needing to be rotated.

### Watching the key wrap migration

`createRequestDecryptor` takes an optional `onKeyWrap` callback that reports which key wrap
algorithm each request actually used. Receivers can use it to tell when senders have finished
migrating off the legacy algorithm. A throw or a rejected promise from the callback is
swallowed, so instrumentation can never fail a request.

The callback fires once the request is fully decrypted, so the count reconciles with the requests
the service served. A request whose payload fails to decrypt is not counted; call `getJWKMetadata`
on that body from the error handler to recover the algorithm it used.

```js
const requestDecryptor = await createRequestDecryptor(privateJWKS, {
  onKeyWrap: ({ kid, alg, legacy }) => {
    metrics.increment('request_crypto.key_wrap', { kid, alg, legacy: String(legacy) });
  },
});
```

### Key identifiers

`addKey(kid)` accepts an optional `kid`. When it is omitted, the key's RFC 7638 thumbprint (SHA-256)
is used, so unnamed keys never collide with each other.
## Releasing

Versions and tags are created by hand; CI only publishes.

1. Bump `version` in `package.json` in a PR against `main`. The `Prepare Package` workflow runs
   lint, build and tests across the supported Node versions on the PR — that is the gate.
2. Tag the merge commit `v<version>` (annotated) and push the tag. The tag must match
   `package.json` exactly; the publish job fails fast if it does not.
3. Publish a GitHub release for that tag. Check **Set as a pre-release** when the version has a
   prerelease suffix.

The `Publish Package to npmjs` workflow then publishes to npm with
[provenance](https://docs.npmjs.com/generating-provenance-statements), authenticating with
[trusted publishing](https://docs.npmjs.com/trusted-publishers) — there is no token to rotate.
The dist-tag is derived from the version: prerelease versions (anything containing a `-`, e.g.
`3.0.0-alpha.1`) publish under **`next`**, everything else under **`latest`**. Install a
prerelease with:

```sh
npm install @elastic/request-crypto@next
```

Note that the npm trusted publisher is bound to this repository *and* to the
`.github/workflows/publish.yml` filename, so adding a separate publish workflow will fail
authentication until the npm-side configuration is updated.

### RFCs followed for implementation details

- JWK RFC: https://tools.ietf.org/html/rfc7517
- JWKS RFC: https://tools.ietf.org/html/rfc7517#appendix-A
- PKCS RFC: https://tools.ietf.org/html/rfc3447
