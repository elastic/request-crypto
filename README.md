# Request Cryptography

<p align="center">
  Encrypt/decrypt request payloads.
</p>

<p align="center">
  <a href="https://badge.fury.io/js/%40elastic%2Frequest-crypto"><img src="https://badge.fury.io/js/%40elastic%2Frequest-crypto.svg" alt="npm version" height="18"></a>
</p>


### Encryption Process (sender side)

1. Randomly Generate a 32-bytes passphrase.
2. Encrypt payload with a strong AES 256 bit key that is derived from the passphrase
3. Select Appropriate Public Key from a list of well-known keys (JWKS) based on `kid`.
4. Use RSA Public key to encrypt the AES key
3. Send encrypted AES key, along with the payload in the request.

### Decryption Process (receiving side)

1. Decrypt the AES Passphrase.
  a. Parse encrypted key from request header.
  b. Select correct Private key based on `kid` from the JWKS pairs.
  c. Decrypt passphrase.
2. Decrypt payload with the AES key that is derived from the decrypted passphrase.

### Why?

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

### Encrypting Payload (client side):

```js
import { encryptPayload } from '@elastic/request-crypto';

const wellKnowns = request.get('<domain>/.well-known');
const {key, payload} = await encryptPayload(input, kid, wellKnowns);

request
  .post(uri)
  .send(payload)
  .set('X-AUTH-KEY', key)
  .set('Content-Type', 'text/plain');
```

### Decrypting Payload (server side):

```js
import { decryptPayload } from '@elastic/request-crypto';

const JWKSPairs = `<fetched from private location>`;
const privateKey = {
  key: await readFileAsync(privateKeyPath, 'utf-8'),
  passphrase: 'your_private_passphrase',
};
const key = request.headers['X-AUTH-KEY'];
const payload = await decryptPayload(request.body, key, JWKSPairs);
```


## Key Rotation: JWKS

Json Web Key Sets are used for key rotation.

#### Why Key rotation?

Having different keys for different usecases/versions and making them accessable on a public URI has multiple benefits. It gives us the flexibility to change the keys without informing the clients or requiring clients to create a new release to use the new keys in case the key gets compromised. Having keys per use case will reduce the surface of damage in case a key compromise happens.

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
const existingJWKS = `<fetched from a .well-known URI>
const jwksManager = await createJWKManager(existingJWKS);
```

### Get Public Keys (for well-known URI)

```js
import { createJWKManager } from '@elastic/request-crypto';
const existingJWKS = `<fetched from a .well-known URI>
const jwksManager = await createJWKManager(existingJWKS);

jwksManager.getPublicJWKS();
```

### Get Full Key pairs Inlcudes private key details

```js
import { createJWKManager } from '@elastic/request-crypto';
const existingJWKS = `<fetched from a .well-known URI>
const jwksManager = await createJWKManager(existingJWKS);

jwksManager.getFullJWKS();
```
