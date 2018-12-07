# Request Cryptography

<p align="center">
  Encrypt/decrypt request payloads.
</p>

<p align="center">
  <a href="https://badge.fury.io/js/%40elastic%2Frequest-crypto"><img src="https://badge.fury.io/js/%40elastic%2Frequest-crypto.svg" alt="npm version" height="18"></a>
</p>


### Encryption Process (sender side)

1. Encrypt payload with a strong AES Key
2. Use RSA Public key to encrypt the AES key
3. Send encrypted AES key, along with the payload in the request.

### Decryption Process (receiving side)

1. Use RSA private key to decrypt header and parse AES Key
2. Decrypt payload with AES Key

### Why?

With RSA, the data to be encrypted is first mapped on to an integer. For
RSA to work, this integer must be smaller than the RSA modulus used. In other words,
public key cannot be used to encrypt large payloads.

The way to solve this is to encrypt the payload with a strong AES key, then encrypt the
AES key with the public key, and send that key along with the request.


### Where to put the Key?
- The private key must not be shared. It must be kept by the receiving side only.
- The public key can be shared. sender side uses the public key to encrypt messages and
send accross the wires.
- The AES Key will be generated on the sender's side uniquely for each client on install
or server lift.


> Notice: Encrypted payloads may fail to be decrypted properly between major versions.



## Usage

### Encrypting Payload (sending side):

```js
import { encryptPayload } from '@elastic/request-crypto'

const publicKey = await readFileAsync(publicKeyPath, 'utf-8');
const {key, payload} = await encryptPayload(data, publicKey);

request
  .post(uri)
  .send(payload)
  .set('X-AUTH-KEY', key)
  .set('Content-Type', 'text/plain');
```

### Decrypting Payload (receiving side):

```js
import { decryptPayload } from '@elastic/request-crypto'

const privateKey = {
  key: await readFileAsync(privateKeyPath, 'utf-8'),
  passphrase: 'your_private_passphrase',
};
const key = request.headers['X-AUTH-KEY']
const payload = await decryptPayload(request.body, key, privateKey)
```

