import { createRequire } from 'module';

import { createRequestDecryptor, KeyWrapInfo, LEGACY_KEY_WRAP_ALGORITHM } from '../src';

import { privateJWKS } from './fixture/private_jwks';

// A namespace import of JSON (`import * as`) also exposes a `default` property. 2.0.4 encrypted
// the parsed document, so load it the same way.
const requireJson = createRequire(import.meta.url);
const frozen = requireJson('./fixture/request-crypto-2.0.4.json') as {
  small: string;
  large: string;
};
const smallPayload = requireJson('./fixture/small_payload.json');
const largePayload = requireJson('./fixture/large_payload.json');

// Packed bodies produced by @elastic/request-crypto@2.0.4 createRequestEncryptor, using the
// public JWK in test/fixture/public_jwks.ts (kid KIBANA, alg RSA-OAEP). Plaintexts are the
// small and large fixtures. 2.0.4 resolved node-jose 2.2.0 and @elastic/node-crypto 1.2.3.
// Unlike encryptWithLegacyKeyWrap, these were not built with jose.

describe('Frozen request-crypto 2.0.4 bodies', () => {
  const cases: Array<{ name: string; body: string; payload: any }> = [
    { name: 'small payload', body: frozen.small, payload: smallPayload },
    { name: 'large payload', body: frozen.large, payload: largePayload },
  ];

  for (const { name, body, payload } of cases) {
    it(`decrypts a 2.0.4 ${name}`, async () => {
      const decryptor = await createRequestDecryptor(privateJWKS);
      expect(await decryptor.decrypt(body)).to.eql(payload);
    });

    it(`reports legacy key wrap for a 2.0.4 ${name}`, async () => {
      const seen: KeyWrapInfo[] = [];
      const decryptor = await createRequestDecryptor(privateJWKS, {
        onKeyWrap: info => seen.push(info),
      });

      const metadata = await decryptor.getJWKMetadata(body);
      expect(metadata.header).to.eql({
        zip: 'DEF',
        enc: 'A128CBC-HS256',
        alg: LEGACY_KEY_WRAP_ALGORITHM,
        kid: 'KIBANA',
      });
      expect(metadata.key.kid).to.equal('KIBANA');
      expect(seen).to.eql([{ kid: 'KIBANA', alg: LEGACY_KEY_WRAP_ALGORITHM, legacy: true }]);
    });
  }
});
