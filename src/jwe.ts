import * as crypto from 'crypto';
import * as zlib from 'zlib';

export const CONTENT_ALGORITHM = 'A128CBC-HS256'; // RFC 7518 §5.2.3
export const ZIP_DEFLATE = 'DEF'; // RFC 7516 §4.1.3 — raw DEFLATE
export const RSA_OAEP_256_ALGORITHM = 'RSA-OAEP-256';
// DEFAULT only — overridable; CVE-2024-28176 class
export const MAX_DECOMPRESSED_SIZE = 250000;

export interface ParsedJWE {
  // JSON.parse of segment 0, insertion order preserved
  protectedHeader: Record<string, string>;
  // Object.keys(protectedHeader) — not sorted, not filtered
  protectedFields: string[];
  // Buffer.from(segments[0], 'ascii') — the VERBATIM segment (RFC 7516 §5.2 step 14)
  aad: Buffer;
  encryptedKey: Buffer;
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

interface CipherParams {
  cekBytes: number;
  keyBytes: number; // cekBytes / 2
  macAlgorithm: string;
  cipherName: string;
}

// A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512 differ only in key split and digest.
// Implements the family generically to insulate the decryptor from any historical enc variation.
function cipherParamsFor(enc: string): CipherParams {
  if (enc === 'A128CBC-HS256') {
    return { cekBytes: 32, keyBytes: 16, macAlgorithm: 'sha256', cipherName: 'aes-128-cbc' };
  }
  if (enc === 'A192CBC-HS384') {
    return { cekBytes: 48, keyBytes: 24, macAlgorithm: 'sha384', cipherName: 'aes-192-cbc' };
  }
  if (enc === 'A256CBC-HS512') {
    return { cekBytes: 64, keyBytes: 32, macAlgorithm: 'sha512', cipherName: 'aes-256-cbc' };
  }
  throw new Error('unsupported "enc" algorithm: ' + enc);
}

// RFC 7518 §5.2.2.1: AL is the AAD bit length as a 64-bit big-endian integer.
// Two 32-bit words, not one: writeUInt32BE(bits, 4) throws ERR_OUT_OF_RANGE past 512 MiB.
// Arithmetic rather than >>> because tslint:recommended enables no-bitwise.
function computeAL(aadByteLength: number): Buffer {
  const al = Buffer.alloc(8);
  const bits = aadByteLength * 8;
  al.writeUInt32BE(Math.floor(bits / 4294967296), 0);
  al.writeUInt32BE(bits % 4294967296, 4);
  return al;
}

// RFC 7518 §5.2.2.1 steps 5-6: HMAC input = AAD ‖ IV ‖ ciphertext ‖ AL.
// tagBytes = keyBytes (half the CEK), per RFC 7518 §5.2.2.1 step 9.
function computeTag(
  macKey: Buffer,
  aad: Buffer,
  iv: Buffer,
  ciphertext: Buffer,
  macAlgorithm: string,
  tagBytes: number
): Buffer {
  return crypto
    .createHmac(macAlgorithm, macKey)
    .update(Buffer.concat([aad, iv, ciphertext, computeAL(aad.length)]))
    .digest()
    .subarray(0, tagBytes);
}

export function parseCompact(input: string | Buffer): ParsedJWE {
  const compact = Buffer.isBuffer(input) ? input.toString('utf8') : input;
  const segments = compact.split('.');
  if (segments.length !== 5) {
    throw new Error('invalid JWE: expected 5 segments, got ' + segments.length);
  }
  const headerB64 = segments[0];
  let protectedHeader: Record<string, string>;
  try {
    const headerJSON = Buffer.from(headerB64, 'base64url').toString('utf8');
    const obj = JSON.parse(headerJSON);
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      throw new Error('header must be a JSON object');
    }
    protectedHeader = obj;
  } catch (e) {
    throw new Error('invalid JWE: ' + e.message);
  }
  const iv = Buffer.from(segments[2], 'base64url');
  const tag = Buffer.from(segments[4], 'base64url');
  const ciphertext = Buffer.from(segments[3], 'base64url');
  if (iv.length !== 16) {
    throw new Error('invalid JWE: IV must be 16 bytes, got ' + iv.length);
  }
  if (tag.length !== 16) {
    throw new Error('invalid JWE: tag must be 16 bytes, got ' + tag.length);
  }
  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new Error(
      'invalid JWE: ciphertext length must be a positive multiple of 16, got ' + ciphertext.length
    );
  }
  return {
    protectedHeader,
    protectedFields: Object.keys(protectedHeader),
    aad: Buffer.from(headerB64, 'ascii'),
    encryptedKey: Buffer.from(segments[1], 'base64url'),
    iv,
    ciphertext,
    tag,
  };
}

// RSA-OAEP CEK unwrap with RFC 3218 / RFC 7516 §11 defence: a failed or wrong-length unwrap
// yields a random CEK so the tag check in decryptContent fails identically. An unwrap failure
// is therefore indistinguishable from a tag failure. Costs one randomBytes on failure only.
export function unwrapKey(parsed: ParsedJWE, privateKey: crypto.KeyObject): Buffer {
  const alg: string = parsed.protectedHeader.alg || '';
  const enc: string = parsed.protectedHeader.enc || '';

  // Determine CEK size from enc without throwing on unknown enc (avoids leaking error type).
  let cekBytes = 32;
  if (enc === 'A192CBC-HS384') {
    cekBytes = 48;
  } else if (enc === 'A256CBC-HS512') {
    cekBytes = 64;
  }

  // oaepHash derived from alg per RFC 7518 §4.3.
  // oaepHash satisfies the RsaPrivateKey union member of privateDecrypt's key parameter.
  // Unknown alg falls through to random CEK so decryptContent's tag check fails identically.
  let oaepHash: string;
  if (alg === 'RSA-OAEP') {
    oaepHash = 'sha1';
  } else if (alg === RSA_OAEP_256_ALGORITHM) {
    oaepHash = 'sha256';
  } else {
    return crypto.randomBytes(cekBytes);
  }

  try {
    return crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
      parsed.encryptedKey
    );
  } catch (e) {
    return crypto.randomBytes(cekBytes);
  }
}

// Decrypts a ParsedJWE's content with the given CEK.
// maxDecompressedSize defaults to MAX_DECOMPRESSED_SIZE when omitted.
export function decryptContent(
  parsed: ParsedJWE,
  cek: Buffer,
  maxDecompressedSize?: number
): Buffer {
  const enc: string = parsed.protectedHeader.enc || '';
  const params = cipherParamsFor(enc);
  const macKey = cek.subarray(0, params.keyBytes);
  const encKey = cek.subarray(params.keyBytes, params.cekBytes);

  // RFC 7518 §5.2.2.2 — verify BEFORE decrypting (encrypt-then-MAC). This makes the CBC
  // padding oracle unreachable: reaching decipher.final() implies a valid HMAC over these
  // exact bytes, so no try/catch is needed there. Inflation happens last, on authenticated data.
  // The length check is NOT decorative: timingSafeEqual THROWS on a length mismatch.
  const expected = computeTag(
    macKey,
    parsed.aad,
    parsed.iv,
    parsed.ciphertext,
    params.macAlgorithm,
    params.keyBytes
  );
  if (parsed.tag.length !== expected.length || !crypto.timingSafeEqual(parsed.tag, expected)) {
    throw new Error('decryption failed');
  }

  const decipher = crypto.createDecipheriv(params.cipherName, encKey, parsed.iv);
  const plaintext = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]);

  // zip: protectedHeader.zip is Record<string,string> so type is string, but is absent (undefined)
  // at runtime when the JWE header has no zip member. Comparison against ZIP_DEFLATE is safe.
  const zip: string = parsed.protectedHeader.zip;
  if (zip === ZIP_DEFLATE) {
    const limit = maxDecompressedSize === undefined ? MAX_DECOMPRESSED_SIZE : maxDecompressedSize;
    try {
      return zlib.inflateRawSync(plaintext, { maxOutputLength: limit });
    } catch (e) {
      if (e && e.code === 'ERR_BUFFER_TOO_LARGE') {
        throw new Error('decompressed payload exceeds limit of ' + limit + ' bytes');
      }
      throw e;
    }
  } else if (zip) {
    throw new Error('unsupported "zip" algorithm: ' + zip);
  }
  return plaintext;
}

export function encryptCompact(
  publicKey: crypto.KeyObject,
  header: { zip?: string; enc: string; alg: string; kid?: string },
  payload: Buffer
): string {
  const params = cipherParamsFor(header.enc);
  const cek = crypto.randomBytes(params.cekBytes);
  const macKey = cek.subarray(0, params.keyBytes);
  const encKey = cek.subarray(params.keyBytes, params.cekBytes);

  // Compress before encryption when zip is requested (per RFC 7516 §5.2 step 3).
  let plaintext: Buffer = payload;
  if (header.zip === ZIP_DEFLATE) {
    plaintext = zlib.deflateRawSync(payload);
  }

  // Emit header in the given object's insertion order.
  // object-literal-sort-keys: false is what permits {zip, enc, alg, kid} — alphabetizing
  // silently changes the wire format and breaks interop with node-jose-produced tokens.
  const headerJSON = JSON.stringify(header);
  const headerB64 = Buffer.from(headerJSON, 'utf8').toString('base64url');
  // AAD is the ASCII-encoded header segment (RFC 7516 §5.2 step 14).
  // Never rebuild the header for AAD — use the segment verbatim so decrypt can reproduce it.
  const aad = Buffer.from(headerB64, 'ascii');

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(params.cipherName, encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = computeTag(macKey, aad, iv, ciphertext, params.macAlgorithm, params.keyBytes);

  // oaepHash derived from alg per RFC 7518 §4.3; satisfies publicEncrypt's RsaPublicKey member.
  const oaepHash = header.alg === RSA_OAEP_256_ALGORITHM ? 'sha256' : 'sha1';
  const encryptedCek = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
    cek
  );

  return [
    headerB64,
    encryptedCek.toString('base64url'),
    iv.toString('base64url'),
    ciphertext.toString('base64url'),
    tag.toString('base64url'),
  ].join('.');
}
