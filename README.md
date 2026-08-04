# Request Cryptography

<p align="center">
  JWK+JWE with AES Encryption for Request Encrypt/decrypt
</p>

<p align="center">
  <a href="https://badge.fury.io/js/%40elastic%2Frequest-crypto"><img src="https://badge.fury.io/js/%40elastic%2Frequest-crypto.svg" alt="npm version" height="18"></a>
</p>

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

### Removing a key

Pass the JWK object (must have a `kid` field) to `removeKey`. All keys with the matching `kid` are
removed; unknown `kid` values are silently ignored.

```js
jwksManager.removeKey(jwksManager.getPublicJWK('kibana1'));
```

### Supported cryptographic profile

| Parameter | Value |
|---|---|
| Key wrap algorithm (`alg`) | `RSA-OAEP` — RSAES-OAEP with SHA-1 and MGF1-SHA-1 |
| Content encryption (`enc`) | `A128CBC-HS256` — AES-128-CBC + HMAC-SHA-256 |
| Compression (`zip`) | `DEF` (raw DEFLATE per RFC 1951) or absent |
| Serialization | JWE compact (5 Base64url segments) |

Tokens produced by earlier versions (node-jose) and tokens produced by 3.x are byte-compatible in
both directions. No re-encryption or coordinated upgrade is required.

### Decompression limit (`maxDecompressedSize`)

By default the decryptor rejects any token whose inflated plaintext exceeds **250,000 bytes**. This
protects against decompression-bomb payloads (CVE-2024-28176 class). The request encryption path
never produces plaintexts above a few kilobytes, so the default gives roughly 7,800× headroom.

If you hold historical tokens whose plaintext exceeds the default — for example because an earlier
version of the library encrypted a large buffer directly through `JWKSManager.encrypt()` — raise
the limit at construction time:

```js
import { createRequestDecryptor } from '@elastic/request-crypto';

const decryptor = await createRequestDecryptor(privateJWKS, {
  maxDecompressedSize: 500_000,  // bytes; must be a positive finite number
});
```

The same option is accepted by `createJWKManager`, `createJWKSManager`, and the `JWKSManager`
constructor.

### Requirements

Node.js ≥ 16 (uses `crypto.createPublicKey({format:'jwk'})` introduced in Node 15.12 and
`Buffer` `'base64url'` encoding introduced in Node 15.7 / 14.18).

### RFCs followed for implementation details

- JWK RFC: https://tools.ietf.org/html/rfc7517
- JWKS RFC: https://tools.ietf.org/html/rfc7517#appendix-A
- JWE RFC: https://tools.ietf.org/html/rfc7516
- JWA RFC: https://tools.ietf.org/html/rfc7518
- PKCS RFC: https://tools.ietf.org/html/rfc3447
