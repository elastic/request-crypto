/**
 * Frozen test vectors generated from node-jose@2.2.0.
 *
 * Generated: 2026-07-31
 * Generator: test/../scratchpad/node-jose-vectors/generate.js
 * node-jose: 2.2.0  @elastic/node-crypto: 1.2.3
 * Key: 1024-bit KIBANA fixture (test/fixture/private_jwks.ts)
 *
 * NEVER regenerate this file without also re-running the reverse interop check.
 * The generator script asserts:
 *   - node-jose decrypts its own zipToken and noZipToken correctly
 *   - node:crypto + zlib built-in token is decryptable by node-jose with
 *     protected == ['zip','enc','alg','kid'] and payload === plaintext
 */

// Plaintext that was encrypted to produce zipToken.
// protected: ['zip', 'enc', 'alg', 'kid']
export const zipPlaintext = '{"test":"node-jose-compat","zip":true,"kid":"KIBANA"}';

// node-jose compact JWE with zip: DEF (zip: true).
// Header (decoded): { zip: 'DEF', enc: 'A128CBC-HS256', alg: 'RSA-OAEP', kid: 'KIBANA' }
export const zipToken =
  'eyJ6aXAiOiJERUYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJLSUJBTkEifQ' +
  '.RUYluzht77t0DRHQazgn2l_90Cdy6lqCGSc3XgMc-5ImvpJaGNmKxjBO-5rsChWnvY1FIqkuYsRM5gRua0P2SCl' +
  'RLAql_S-PL3p5ieueD2Vql0RFSHVksQAM5WvBuaYgP31A9RCneLWukBl7L_dBzUYXhzDQ_YsWVHYoo2R_-6c' +
  '.NpbseF3iOk9KFwB4dFvkGQ' +
  '.wvKylM7Y1PKgGiUP1pozltCEG8uq6YnBELeT5fBBKEJ4BU5xoz1goVzczq4s_PlB-mlRAnIwHMhajtO7F-ZZnQ' +
  '.LpMKJIPctyKLzoo2P7FIEg';

// Plaintext that was encrypted to produce noZipToken.
// protected: ['enc', 'alg', 'kid']
export const noZipPlaintext = '{"test":"node-jose-compat","zip":false,"kid":"KIBANA"}';

// node-jose compact JWE without zip.
// Header (decoded): { enc: 'A128CBC-HS256', alg: 'RSA-OAEP', kid: 'KIBANA' }
export const noZipToken =
  'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJLSUJBTkEifQ' +
  '.AbRdvf7LXF39xwsg4z-dfGysjk3iPXJhEDOWdj0zu1LSSy1xbYxqe_2AzRAL1DkB41-0uC16IRPVbRyaUnGdVpK' +
  'DNcp-E1xQqfAa1a3rajtX8TtzcUq26rtOtbp1VAiSlzT6qCGcYEJmu4_3a7glylVaWzlP1m5b9-PRoeCGNsA' +
  '.wkPtsnbazNLShZaA-ZpRVQ' +
  '.KpwJduhqQ4GI1-IUyIPMAGvMpQPFKI1WZQd5FdlJMbmDhYdvnX1xB81e5PlHj8iHnu4StmsjNPgGcdNaUOcvIw' +
  '.XkdafuH5ho9KmuJP2eK40A';

// Plaintext (before AES+JWE) for the full packed-body vector below.
export const packedBodyPlaintext = '{"test":"packed-body-compat","source":"node-jose"}';

// Full request-crypto wire format: packBody(encryptedAESKey, encryptedPayload).
// Built with: node-jose JWE (zip:true) wrapping a random 32-byte AES key,
//             @elastic/node-crypto AES encrypting packedBodyPlaintext,
//             node-jose util.base64url.encode of the JSON envelope.
// Decryptable end-to-end by createRequestDecryptor(privateJWKS).
export const packedBody =
  'eyJlbmNyeXB0ZWRBRVNLZXkiOiJleUo2YVhBaU9pSkVSVVlpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkl' +
  'pd2lZV3huSWpvaVVsTkJMVTlCUlZBaUxDSnJhV1FpT2lKTFNVSkJUa0VpZlEuT2wyYXlpNU9md2tqQ21EU0xXbH' +
  'R2U3ZmLXVvNGlPcWc5TUFCM0tVakNUVkxXOW8wODJoUllHQ19rWlY3Z0NzUDBVVUJNZXJrTlZJT2o2Y0QwLW1E' +
  'OEg1eXc3X1hiaDYxWVpKZHNmQmdtMXBtdzdsM2FHQnJxMm5ucmc0VzZZekZuODRhTUk1R0s2RGdiUkdRZTIwcFN' +
  'aNzlTbXp6ZEJVVnVWMnlER00yUTdRLmF6UTNxUnNaUG50ZTVxdTlkS1Roc1EubThrTVVUZkZOUWlFTkcxaklhVl' +
  'RHR3VpOHBNSEJCQmcyQ1hralc3anE1MWJyU2cwLUpiWHdKazRCUVBKTWFoVC5KWDBld0d0MGdJaldEUkhZUzFyVj' +
  'FBIiwiZW5jcnlwdGVkUGF5bG9hZCI6ImRwSWQyc1VTWFdNekp4UmNRSHBRcWcwOFJ0b1pzL2FSYk1CQktTTGgv' +
  'UXN2OWZhNTV1cG5NR2NmY2ZveFVQSXkrYlp4OXZrSG1TYTdCaE03L0RwejdGRG13K3BVUjd6K2RkcDFsclc3bnp' +
  'ENDhMTW8wYVM0Qk9EdjArVHE5ZFIvVGJXYVRWbjh5VkNxcGdmOHYraUhXclRnRERad1ZTZUwxOWFGQmw4bTZWS2' +
  'tzbjdndU1KUHlOQlFXYlNKeGc9PSJ9';

// Sentinel inputs and output for packBody encoding test.
// packedBodySentinel === Buffer.from(JSON.stringify({
//   encryptedAESKey: packedBodySentinelAESKey,
//   encryptedPayload: packedBodySentinelPayload,
// }), 'utf8').toString('base64url')
// This value is deterministic (no crypto) and verifies Buffer.toString('base64url')
// is byte-identical to node-jose's util.base64url.encode.
export const packedBodySentinelAESKey = 'sentinel-aes-key-for-pack-test';
export const packedBodySentinelPayload = 'sentinel-encrypted-payload-value';
export const packedBodySentinel =
  'eyJlbmNyeXB0ZWRBRVNLZXkiOiJzZW50aW5lbC1hZXMta2V5LWZvci1wYWNrLXRlc3QiLCJlbmNyeXB0ZWRQYXlsb2FkIjoic2VudGluZWwtZW5jcnlwdGVkLXBheWxvYWQtdmFsdWUifQ';

// JWKMetadata shape node-jose returns from decrypt result.
// Use to assert our metadata() snapshot matches exactly.
export const zipKeyMeta = {
  kty: 'RSA',
  kid: 'KIBANA',
  use: 'enc',
  alg: 'RSA-OAEP',
  length: 1024,
};
