import {
  CONTENT_ALGORITHM,
  decryptContent,
  encryptCompact,
  MAX_DECOMPRESSED_SIZE,
  parseCompact,
  ZIP_DEFLATE,
} from '../src/jwe';
import { createJWKSManager } from '../src/jwks';
import { createRequestDecryptor, packBody } from '../src/request';

import { privateJWKS } from './fixture/private_jwks';
import { publicJWKS } from './fixture/public_jwks';

// RFC 7518 Appendix B.1 — AES_128_CBC_HMAC_SHA_256 fixed test vector
// https://www.rfc-editor.org/rfc/rfc7518#appendix-B.1
// All values verified against the RFC hex dump (fetched 2026-08-04).
const B1_CEK = Buffer.from(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'hex'
);
const B1_IV = Buffer.from('1af38c2dc2b96ffdd86694092341bc04', 'hex');
// RFC 7518 B.1 plaintext (128 bytes) — exactly fills 8 CBC blocks; PKCS7 adds a 9th.
// "A cipher system must not be required to be secret, and it must be able to
//  fall into the hands of the enemy without inconvenience"
const B1_PLAINTEXT = Buffer.from(
  'A cipher system must not be required to be secret, ' +
    'and it must be able to fall into the hands of the enemy without inconvenience',
  'ascii'
);
// RFC 7518 B.1 AAD (42 bytes) — "The second principle of Auguste Kerckhoffs"
// AL = 42 * 8 = 336 = 0x150 (verified: RFC shows AL = 00 00 00 00 00 00 01 50)
const B1_AAD = Buffer.from('The second principle of Auguste Kerckhoffs', 'ascii');
// 144 bytes: AES-128-CBC(ENC_KEY, IV, PKCS7-padded-plaintext); 9 × 16-byte rows from RFC B.1 hex.
const B1_CIPHERTEXT = Buffer.from(
  'c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9' +
    'a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336' +
    '09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b' +
    '384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5' +
    '4b8851ffb598f7f80074b9473c82e2db',
  'hex'
);
const B1_TAG = Buffer.from('652c3fa36b0a7c5b3219fab3a30bc1c4', 'hex');

// RFC 7516 Appendix A.2 — content-layer vector (alg=RSA1_5, but CEK/IV/ciphertext/tag are valid)
// https://www.rfc-editor.org/rfc/rfc7516#appendix-A.2
// CEK from A.2.1, IV/ciphertext/tag taken from the compact JWE in A.2.5.
const A2_CEK = Buffer.from(
  '04d31fc5549dfcfe0b649dfa3faa6ace6b7cd42d6f6b09dbc8b100f08f9c2ccf',
  'hex'
);
const A2_IV = Buffer.from('AxY8DCtDaGlsbGljb3RoZQ', 'base64url');
const A2_AAD = Buffer.from('eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', 'ascii');
const A2_CIPHERTEXT = Buffer.from('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY', 'base64url');
const A2_TAG = Buffer.from('9hH0vgRfYgPnAHOd8stkvw', 'base64url');
const A2_PLAINTEXT = Buffer.from('Live long and prosper.', 'ascii');

describe('RFC spec vectors', () => {
  describe('RFC 7518 Appendix B.1 — AES_128_CBC_HMAC_SHA_256', () => {
    it('decryptContent reproduces the spec plaintext', () => {
      const parsed = {
        protectedHeader: { enc: CONTENT_ALGORITHM },
        protectedFields: ['enc'],
        aad: B1_AAD,
        encryptedKey: Buffer.alloc(0),
        iv: B1_IV,
        ciphertext: B1_CIPHERTEXT,
        tag: B1_TAG,
      };
      const pt = decryptContent(parsed as any, B1_CEK);
      expect(pt).to.eql(B1_PLAINTEXT);
    });
  });

  describe('RFC 7516 Appendix A.2 — content-layer vector', () => {
    it('decryptContent authenticates and decrypts A.2 ciphertext', () => {
      const parsed = {
        protectedHeader: { enc: CONTENT_ALGORITHM },
        protectedFields: ['enc'],
        aad: A2_AAD,
        encryptedKey: Buffer.alloc(0),
        iv: A2_IV,
        ciphertext: A2_CIPHERTEXT,
        tag: A2_TAG,
      };
      const pt = decryptContent(parsed as any, A2_CEK);
      expect(pt).to.eql(A2_PLAINTEXT);
    });
  });
});

describe('JWE tamper detection', () => {
  let validToken: string;
  let manager: any;

  before(async () => {
    manager = await createJWKSManager(privateJWKS);
    validToken = await manager.encrypt('KIBANA', Buffer.from('test-payload', 'utf8'));
  });

  function tamperByte(token: string, segIndex: number): string {
    const segs = token.split('.');
    const buf = Buffer.from(segs[segIndex], 'base64url');
    buf[0] = (buf[0] + 1) % 256;
    segs[segIndex] = buf.toString('base64url');
    return segs.join('.');
  }

  it('rejects tampered authentication tag', async () => {
    let errorMessage = '';
    try {
      await manager.decrypt(tamperByte(validToken, 4));
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('decryption failed');
  });

  it('rejects tampered ciphertext — error is "decryption failed", not a padding oracle', async () => {
    let errorMessage = '';
    try {
      await manager.decrypt(tamperByte(validToken, 3));
    } catch (err) {
      errorMessage = err.toString();
    }
    // MAC-before-decrypt: CBC padding error must never surface
    expect(errorMessage).to.include('decryption failed');
    expect(errorMessage).to.not.include('bad decrypt');
  });

  it('rejects tampered protected header (AAD covers it)', async () => {
    const segs = validToken.split('.');
    segs[0] = segs[0] + 'X';
    let errorMessage = '';
    try {
      await manager.decrypt(segs.join('.'));
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage.length).to.be.greaterThan(0);
  });
});

describe('JWE parsing validation', () => {
  let manager: any;
  before(async () => {
    manager = await createJWKSManager(privateJWKS);
  });

  it('rejects 4-segment compact', async () => {
    let errorMessage = '';
    try {
      await manager.decrypt('a.b.c.d');
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('5 segments');
  });

  it('rejects 6-segment compact', async () => {
    let errorMessage = '';
    try {
      await manager.decrypt('a.b.c.d.e.f');
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('5 segments');
  });

  it('rejects non-JSON header', async () => {
    const bad = Buffer.from('not-json').toString('base64url') + '.b.c.d.e';
    let errorMessage = '';
    try {
      await manager.decrypt(bad);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage.length).to.be.greaterThan(0);
  });

  it('rejects header that is a JSON string (not object)', async () => {
    const bad = Buffer.from('"string"').toString('base64url') + '.b.c.d.e';
    let errorMessage = '';
    try {
      await manager.decrypt(bad);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('object');
  });
});

describe('key-not-found scenarios', () => {
  let manager: any;
  let token: string;

  before(async () => {
    manager = await createJWKSManager(privateJWKS);
    token = await manager.encrypt('KIBANA', Buffer.from('hello', 'utf8'));
  });

  function replaceHeader(t: string, header: object): string {
    const segs = t.split('.');
    segs[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
    return segs.join('.');
  }

  it('RSA1_5 alg yields no key found', async () => {
    const t = replaceHeader(token, { enc: CONTENT_ALGORITHM, alg: 'RSA1_5', kid: 'KIBANA' });
    let errorMessage = '';
    try {
      await manager.decrypt(t);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.equal('Error: no key found');
  });

  it('dir alg yields no key found', async () => {
    const t = replaceHeader(token, { enc: CONTENT_ALGORITHM, alg: 'dir', kid: 'KIBANA' });
    let errorMessage = '';
    try {
      await manager.decrypt(t);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.equal('Error: no key found');
  });

  it('unknown kid yields no key found', async () => {
    const t = replaceHeader(token, { enc: CONTENT_ALGORITHM, alg: 'RSA-OAEP', kid: 'UNKNOWN' });
    let errorMessage = '';
    try {
      await manager.decrypt(t);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.equal('Error: no key found');
  });

  it('public-only store yields no key found', async () => {
    const pubManager = await createJWKSManager(publicJWKS);
    let errorMessage = '';
    try {
      await pubManager.decrypt(token);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.equal('Error: no key found');
  });
});

describe('unsupported algorithms', () => {
  it('unsupported enc (A256GCM) throws at decryptContent', () => {
    const parsed = {
      protectedHeader: { enc: 'A256GCM' },
      protectedFields: ['enc'],
      aad: Buffer.alloc(0),
      encryptedKey: Buffer.alloc(0),
      iv: Buffer.alloc(16),
      ciphertext: Buffer.alloc(16),
      tag: Buffer.alloc(16),
    };
    let errorMessage = '';
    try {
      decryptContent(parsed as any, Buffer.alloc(32));
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('unsupported "enc"');
  });

  it('unsupported zip (GZ) throws after successful MAC', async () => {
    const manager = await createJWKSManager(privateJWKS);
    const key = manager.store.get('KIBANA');
    // encryptCompact with zip: 'GZ' stores uncompressed content but labels it 'GZ' — MAC is valid
    const gzToken = encryptCompact(
      key.publicKey,
      { zip: 'GZ', enc: CONTENT_ALGORITHM, alg: 'RSA-OAEP', kid: 'KIBANA' },
      Buffer.from('hello', 'utf8')
    );
    let errorMessage = '';
    try {
      await manager.decrypt(gzToken);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('unsupported "zip"');
  });
});

describe('decompression bomb protection', () => {
  let manager: any;
  let bombToken: string;

  before(async () => {
    manager = await createJWKSManager(privateJWKS);
    // Payload just above the default limit; deflateRaw compresses it well but inflate will exceed cap
    const bigPayload = Buffer.alloc(MAX_DECOMPRESSED_SIZE + 1, 0x41);
    bombToken = await manager.encrypt('KIBANA', bigPayload);
  });

  it('rejects payload exceeding MAX_DECOMPRESSED_SIZE by default', async () => {
    let errorMessage = '';
    try {
      await manager.decrypt(bombToken);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include(String(MAX_DECOMPRESSED_SIZE));
  });

  it('succeeds when limit is raised above payload size', async () => {
    const raised = await createJWKSManager(privateJWKS, {
      maxDecompressedSize: MAX_DECOMPRESSED_SIZE + 100,
    });
    const result = await raised.decrypt(bombToken);
    expect(Buffer.isBuffer(result.plaintext)).to.equal(true);
    expect(result.plaintext.length).to.equal(MAX_DECOMPRESSED_SIZE + 1);
  });

  it('rejects at a limit just below payload size', async () => {
    const tight = await createJWKSManager(privateJWKS, {
      maxDecompressedSize: MAX_DECOMPRESSED_SIZE,
    });
    let errorMessage = '';
    try {
      await tight.decrypt(bombToken);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include(String(MAX_DECOMPRESSED_SIZE));
  });

  it('error message names the effective limit when raised', async () => {
    // Build a token slightly above the raised limit
    const raisedLimit = 50000;
    const raised = await createJWKSManager(privateJWKS, { maxDecompressedSize: raisedLimit });
    const bigPayload = Buffer.alloc(raisedLimit + 1, 0x42);
    const overToken = await raised.encrypt('KIBANA', bigPayload);
    let errorMessage = '';
    try {
      await raised.decrypt(overToken);
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include(String(raisedLimit));
  });

  it('option is reachable via createRequestDecryptor', async () => {
    const raised = await createRequestDecryptor(privateJWKS, {
      maxDecompressedSize: MAX_DECOMPRESSED_SIZE + 100,
    });
    // Pack bombToken as the AES key portion; the decrypt will fail at AES level (not JWE level)
    const packed = packBody(bombToken, 'dummy');
    let errorMessage = '';
    try {
      await raised.decrypt(packed);
    } catch (err) {
      errorMessage = err.toString();
    }
    // Should NOT fail with 'decompressed payload exceeds limit'
    expect(errorMessage).to.not.include('decompressed payload exceeds limit');
  });

  it('constructor throws on maxDecompressedSize: 0', async () => {
    let errorMessage = '';
    try {
      await createJWKSManager(undefined, { maxDecompressedSize: 0 });
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('maxDecompressedSize');
  });

  it('constructor throws on negative maxDecompressedSize', async () => {
    let errorMessage = '';
    try {
      await createJWKSManager(undefined, { maxDecompressedSize: -1 });
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('maxDecompressedSize');
  });

  it('constructor throws on NaN', async () => {
    let errorMessage = '';
    try {
      await createJWKSManager(undefined, { maxDecompressedSize: NaN });
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('maxDecompressedSize');
  });

  it('constructor throws on Infinity', async () => {
    let errorMessage = '';
    try {
      await createJWKSManager(undefined, { maxDecompressedSize: Infinity });
    } catch (err) {
      errorMessage = err.toString();
    }
    expect(errorMessage).to.include('maxDecompressedSize');
  });
});

describe('decrypt result contains no private material', () => {
  it('result.key has no private components', async () => {
    const manager = await createJWKSManager(privateJWKS);
    const token = await manager.encrypt('KIBANA', Buffer.from('hello', 'utf8'));
    const result = await manager.decrypt(token);
    const keyKeys = Object.keys(result.key);
    expect(keyKeys).to.not.include('d');
    expect(keyKeys).to.not.include('p');
    expect(keyKeys).to.not.include('q');
  });
});
