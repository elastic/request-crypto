# Request Cryptography

<p align="center">
  JWE+POP with AES Encryption for Request Encrypt/decrypt
</p>

<p align="center">
  <a href="https://badge.fury.io/js/%40elastic%2Frequest-crypto"><img src="https://badge.fury.io/js/%40elastic%2Frequest-crypto.svg" alt="npm version" height="18"></a>
</p>

### High level overview

There are 4 parts involved for JWK+POP:
- Mediator (browser)
- Sender (kibana server)
- Well Known URI (Telemetry Service)
- Reciever (Telemetry service)

1. Mediator hits the well-known URI and provides the sender Identity.
2. Well-known URI responds with signed JWKS based on provided identity.
3. Mediator sends the sender the signed JWKS.
4. Sender gets the needed JWK from the JWKS based on `kid`  and verifies the signature.
   1. Sender selects JWK based on `kid`.
   2. Sender verifies JWK signature based on `cnf`.
   3. Sender encrypts data with a randomly Generate a 32-bytes AES passphrase.
   4. Sender encrypts payload with a strong AES 256 bit key that is derived from the passphrase.
   5. Sender encrypts the AES key with the selected JWK.
   6. Sender sends the Mediator the AES encrypted payload and the JWK encrypted AES key.
5. Mediator sends the enrypted payload to Reciever.
6. Reciever gets the needed data from mediators
   1. Reciever decrypts AES key using the corrisponsing public key's pair.
   2. Reciever decrypts payload with decrypted AES key.
   3. Reciever processes payload.

### Why?

JWK are a way to pass public/private keys (RSA) in JSON format. POP (Proof of Possession) allows an untrusted source (browser) to act as a mediator in passing the JWKS.

With RSA, the data to be encrypted is first mapped on to an integer. For
RSA to work, this integer must be smaller than the RSA modulus used. In other words,
public key cannot be used to encrypt large payloads.

The way to solve this is to encrypt the payload with a strong AES key, then encrypt the
AES key with the public key, and send that key along with the request.

RSA is almost never used for data encryption. The approach we've taken here is the common one (TLS, PGP etc do the same in principle) where a symmetric key is used for data encryption and that key is then encrypted with RSA. Size is one constraint, the other is performance as RSA is painfully slow compared to a symmetric key cipher such as AES.


### Where to put the Key?
- RSA JSON Public Key Sets are kept in a JSON Web Key Set on a `.well-known` URI.
- RSA Private Keys are kept private and must never be shared.
- The AES Passphrase will be generated on the sender's side uniquely on each request.

## Usage

Request crypto has two main servicers `Encryptor` and `Decryptor`.
`Encryptor` is used by the sending side. while `Decryptor` is used by the well-known URI and reciever side.



#### Sender Side (ie Kibana)

```js
import { createRequestEncryptor } from '@elastic/request-crypto';
import * as fs from 'fs';

async function managePOPJWK() {
  const privatePOPKeys = await fs.readAsync('...', 'utf8');
  cont requestEncryptor = await createRequestEncryptor(privatePOPKeys);
  if(!privatePOPKeys) {
    const popKey = await requestEncryptor.addPOPJWK();
    await fs.writeAsync(popKey);
  }
}

function appendIdentityToHeader(req) {
  req.headers['identity'] = requestEncryptor.getIdentity();
}

async function onInit() {
  await managePOPJWK();
}

function onAllRequests(req) {
  appendIdentityToHeader(req)
}

function TelemetryEndpointRoute(req, res) {
  const signedWellKnows = req.body;
  const metrics = await getCollectors();
  try {
    const encryptedPaylaod = await requestEncryptor.verifyAndEncrypt(metrics, 'kibana', signedWellKnows)
    res.end(encryptedPaylaod);
  } catch(err) {
    res.status(500).end(`Error: ${err}`);
  }
}
```


#### Mediator (ie browser)

```js
async function requestWellKnowns(identity) {
  return fetch('https://telemetry.elastic.co/.well-known', {
    method: 'GET',
    headers: { identity }
  });
}

async function getTelemetryMetrics(identity) {
  const wellKnowns = await requestWellKnowns(identity);
  return fetch(server.telemetryEndpoint, {
    method: 'POST',
    body: { wellKnowns }
  });
}

async function sendTelemetryMetrics() {
  const identity = server.req.headers.identity;
  const metrics = await getTelemetryMetrics(identity);
  return fetch('https://telemetry.elastic.co/v2/xpack', {
    body: metrics
  });
}
```

#### well-known URI

```js
import { createRequestDecryptor } from '@elastic/request-crypto';
import privateJWKS from './privateJWKS';

async function handler (event, context, callback) {
  const identity = getHeader(event, 'identity');
  const requestDecryptor = await createRequestDecryptor(privateJWKS);
  const signedPublicJWKS = await requestDecryptor.getWellKnowns(identity);

  return {
    status: '200',
    body: signedPublicJWKS,
  }
}
```

#### Recieving side (ie Telemetry Service)

```js
import { createRequestDecryptor } from '@elastic/request-crypto';
import privateJWKS from './privateJWKS';

async function handler (event, context, callback) {
  const requestDecryptor = await createRequestDecryptor(privateJWKS);
  const {payload, key} = event.body;
  const decryptedPayload = await requestDecryptor.decryptPayload(payload, key);

  // ... handle payload
}
```

## Key Rotation: JWKS

Json Web Key Sets are used for key rotation.

#### Why Key rotation?

Key rotation gives extra flexibility to change the keys without informing the sender side or requiring senders to create a new release to use the new keys in case the key gets compromised. Having keys per use case will reduce the surface of damage in case a key compromise happens.

#### Do I need a `.well-known` URI

Having the URI `.well-known` indicates that the implementation is following the JWTS RFC. This URI is also required to register the endpoint with `IANA` in case there is a need for public developer consumption.

### Create a new keyset

```js
import { createJWKManager } from '@elastic/request-crypto';
const jwksManager = await createJWKManager();
await jwksManager.addKey(`<kid>`);
```

### Use existing keyset

```js
import { createJWKManager } from '@elastic/request-crypto';
const existingJWKS = `<fetched from a .well-known URI>`
const jwksManager = await createJWKManager(existingJWKS);

// get public key components
jwksManager.getPublicJWKS();
// get full Key pairs Inlcuding private components
jwksManager.getPrivateJWKS();
```
